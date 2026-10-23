//! `chain.*` end to end (design 0005): the real binary, with the test
//! playing main. Main answers the core's `shell.rpc`, `shell.verified` and
//! `shell.blockscout` requests from scripts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::{Core, Wire, dirs, fragmented, request, spawn};
use serde_json::{Value, json};

const MIB: usize = 1 << 20;

/// A signed transaction and its hash (vectors/chain.json).
const RAW: &str = "0xf85f8001825208941111111111111111111111111111111111111111018026a045df4733a45ed06c5628f22221a73e0b2faa3959f649cc47e6c2a15c9792ae07a00ea422e4923de6e5b4c52d7fbd39046e96acf73b2037a5f11918ec6c2a64b40a";
const HASH: &str = "0xdff97f6d2d938656e056527357e2ee12f38c03923ab1d11bc556fb5cc123e578";
const ADDRESS: &str = "0x1111111111111111111111111111111111111111";

fn core() -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello_fragments();
    (root, core)
}

/// Chain 1's snapshot: `read` as its read order, `rpc` its endpoints, a
/// quorum of 3 agreeing on 2 with `timeout_ms`.
fn snapshot(read: &[&str], rpc: &[&str], timeout_ms: u64) -> Value {
    json!({
        "chain_id": 1,
        "display_name": "Ethereum",
        "read_order": read,
        "broadcast_order": ["direct"],
        "quorum": { "k": 3, "m": 2, "timeout_ms": timeout_ms },
        "rpc": rpc.iter().map(|e| json!({ "endpoint": e, "user_configured": false })).collect::<Vec<_>>(),
        "prover": null,
        "myotis": false,
        "blockscout": null,
    })
}

/// Reads until the response to main's request `id`: the core's own
/// requests and cancels use another ID space, so they are skipped by type.
fn response_to(core: &mut Core, id: u64) -> Value {
    loop {
        let message = core.recv();
        if message["type"] == "response" && message["id"] == id {
            return message;
        }
    }
}

fn call(core: &mut Core, id: u64, method: &str, params: Value) -> Value {
    core.send(&request(id, method, params));
    response_to(core, id)
}

fn configure(core: &mut Core, id: u64, chains: &[Value]) -> Value {
    let reply = call(core, id, "chain.configure", json!({ "chains": chains }));
    assert!(reply["result"].is_object(), "{reply}");
    reply["result"]["generations"].clone()
}

/// `chain.request`'s params for a read.
fn read(method: &str, params: Value) -> Value {
    json!({
        "chain_id": 1,
        "method": method,
        "params": params,
        "include_trust": false,
        "background": false,
        "profile": "default",
        "deadline_ms": 60_000,
    })
}

/// Main's `shell.rpc` result for an answer `text`.
fn rpc(text: &str) -> Value {
    json!({ "result": {
        "status": 200,
        "body": base64::engine::general_purpose::STANDARD.encode(text),
    } })
}

fn rpc_result(result: &str) -> Value {
    rpc(&format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#))
}

fn failure(code: &str) -> Value {
    json!({ "error": { "code": code, "message": "Transport failure" } })
}

/// The JSON-RPC body of a `shell.rpc` request.
fn body(request: &Value) -> Value {
    serde_json::from_str(request["params"]["body"].as_str().unwrap()).unwrap()
}

fn rpc_method(request: &Value) -> String {
    if request["method"] == "shell.rpc" {
        body(request)["method"].as_str().unwrap().to_owned()
    } else {
        String::new()
    }
}

/// What main saw of the core while it played.
#[derive(Default)]
struct Seen {
    /// The core's requests, in the order they arrived.
    requests: Vec<Value>,
    /// The IDs of the core's cancels.
    cancels: Vec<u64>,
}

/// Plays main until the response to `id`: each of the core's requests
/// goes to `answer`, which gives main's terminal reply (its `result` or
/// `error`) or `None` to hold it.
fn serve(
    core: &mut Core,
    id: u64,
    mut answer: impl FnMut(&Value) -> Option<Value>,
) -> (Value, Seen) {
    let mut seen = Seen::default();
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("request") => {
                if let Some(outcome) = answer(&message) {
                    reply(core, &message, outcome);
                }
                seen.requests.push(message);
            }
            Some("cancel") => seen.cancels.push(message["id"].as_u64().unwrap()),
            Some("response") if message["id"] == id => return (message, seen),
            _ => panic!("unexpected {message}"),
        }
    }
}

/// Main's terminal reply to one of the core's requests: in fragments of
/// half a frame when it is over one (design 0005, Frames).
fn reply(core: &mut Core, request: &Value, outcome: Value) {
    let mut message = json!({ "type": "response", "id": request["id"] });
    for (key, value) in outcome.as_object().unwrap() {
        message[key] = value.clone();
    }
    let len = message.to_string().len();
    if len < MIB {
        core.send(&message);
    } else {
        for frame in fragmented(&message, len.div_ceil(MIB / 2)) {
            core.send_raw(&frame);
        }
    }
}

/// The core's next `count` requests, other messages set aside.
fn requests_only(core: &mut Core, count: usize) -> Vec<Value> {
    let mut requests = Vec::new();
    while requests.len() < count {
        let message = core.recv();
        if message["type"] == "request" {
            requests.push(message);
        }
    }
    requests
}

#[test]
fn a_quorum_read_through_main() {
    let (_root, mut core) = core();
    let generations = configure(
        &mut core,
        2,
        &[snapshot(&["quorum"], &["a", "b", "c"], 5000)],
    );
    assert_eq!(generations, json!({ "1": 1 }));
    let mut params = read("eth_call", json!([{ "to": ADDRESS }, "latest"]));
    params["include_trust"] = json!(true);
    core.send(&request(3, "chain.request", params));
    // Each member answers the same value, spelled differently; the first
    // two to arrive agree.
    let answers = [
        r#"{"b":1,"a":[1e2]}"#,
        r#"{"a":[100],"b":1}"#,
        r#"{"a":[100],"b":1}"#,
    ];
    let mut next = 0;
    let (reply, seen) = serve(&mut core, 3, |request| {
        assert_eq!(request["method"], "shell.rpc");
        let params = &request["params"];
        assert_eq!(params["policy"], "plain");
        assert_eq!(params["max_bytes"], 18 * MIB);
        assert_eq!(params["generation"], 1);
        let deadline = params["deadline_ms"].as_u64().unwrap();
        assert!(deadline > 0 && deadline <= 5000, "{deadline}");
        let body = body(request);
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["method"], "eth_call");
        assert_eq!(body["params"], json!([{ "to": ADDRESS }, "latest"]));
        next += 1;
        Some(rpc_result(answers[next - 1]))
    });
    let endpoints: Vec<&str> = seen
        .requests
        .iter()
        .map(|r| r["params"]["endpoint"].as_str().unwrap())
        .collect();
    assert_eq!(endpoints, ["a", "b", "c"]);
    let result = &reply["result"];
    // The first agreeing answer's own text, embedded as it came: its keys
    // in its order, its number as it spelled it.
    let agreed = result["result"].as_object().unwrap();
    assert_eq!(agreed.keys().collect::<Vec<_>>(), ["b", "a"], "{reply}");
    assert_eq!(agreed["a"][0].as_f64(), Some(100.0));
    assert!(agreed["a"][0].is_f64(), "1e2 stays a double: {reply}");
    assert_eq!(result["source"], "quorum");
    assert_eq!(result["verified"], true);
    assert_eq!(result["undefined_keys"], json!([]));
    assert_eq!(result["generation"], 1);
    // Endpoint references, for main to substitute with hosts.
    let trust = &result["trust"];
    assert!(
        trust["agreed"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["ref"].is_string()),
        "{trust}"
    );
    // The vault still answers.
    assert!(call(&mut core, 1000, "vault.status", json!({}))["result"].is_object());
}

/// `exclude_sources` (design 0005, Methods main calls): the router's
/// `excludeSources` over the wire, on top of the profile's exclusions.
#[test]
fn a_read_skips_the_sources_it_excludes() {
    // The core offers the field; main sends it to no other core.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello_fragments();
    assert!(
        hello["result"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("exclude_sources")),
        "{hello}"
    );
    configure(
        &mut core,
        2,
        &[snapshot(&["quorum", "direct"], &["a", "b", "c"], 5000)],
    );
    let mut params = read("eth_getTransactionReceipt", json!([HASH]));
    params["exclude_sources"] = json!(["quorum"]);
    core.send(&request(3, "chain.request", params));
    // Only Direct is asked: its first endpoint, which answers.
    let (reply, seen) = serve(&mut core, 3, |_| Some(rpc_result("null")));
    assert_eq!(reply["result"]["source"], "direct", "{reply}");
    assert_eq!(reply["result"]["verified"], false);
    let endpoints: Vec<&str> = seen
        .requests
        .iter()
        .map(|r| r["params"]["endpoint"].as_str().unwrap())
        .collect();
    assert_eq!(endpoints, ["a"]);

    // Nothing left to ask: today's text, naming what was dropped.
    let mut params = read("eth_blockNumber", json!([]));
    params["exclude_sources"] = json!(["direct", "quorum"]);
    let reply = call(&mut core, 4, "chain.request", params);
    assert_eq!(reply["error"]["data"]["kind"], "core", "{reply}");
    assert_eq!(
        reply["error"]["data"]["message"],
        "No chain source left for eth_blockNumber on chain 1: read order [quorum, direct], \
         excluded for this request: quorum, direct"
    );
}

#[test]
fn exclude_sources_names_known_sources_once() {
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    for (id, excluded) in [
        (3, json!(["nobody"])),
        (4, json!(["colibri", "colibri"])),
        (5, json!(["Colibri"])),
        (6, json!([1])),
        (7, json!("colibri")),
        (8, json!(null)),
    ] {
        let mut params = read("eth_blockNumber", json!([]));
        params["exclude_sources"] = excluded.clone();
        let reply = call(&mut core, id, "chain.request", params);
        assert_eq!(
            reply["error"],
            json!({ "code": "invalid_argument", "message": "Invalid parameters" }),
            "{excluded}: {reply}"
        );
    }
    // Every known source, and none at all, are fine.
    let mut params = read("eth_blockNumber", json!([]));
    params["exclude_sources"] = json!(["myotis", "colibri", "quorum", "blockscout"]);
    core.send(&request(9, "chain.request", params));
    let (reply, _) = serve(&mut core, 9, |_| Some(rpc_result(r#""0x10""#)));
    assert_eq!(reply["result"]["result"], "0x10", "{reply}");
    let mut params = read("eth_blockNumber", json!([]));
    params["exclude_sources"] = json!([]);
    core.send(&request(10, "chain.request", params));
    let (reply, _) = serve(&mut core, 10, |_| Some(rpc_result(r#""0x11""#)));
    assert_eq!(reply["result"]["result"], "0x11", "{reply}");
}

#[test]
fn direct_after_a_quorum_timeout() {
    let (_root, mut core) = core();
    configure(
        &mut core,
        2,
        &[snapshot(&["quorum", "direct"], &["a", "b", "c", "d"], 500)],
    );
    core.send(&request(
        3,
        "chain.request",
        read("eth_blockNumber", json!([])),
    ));
    let started = Instant::now();
    // The quorum's members never answer; Direct asks the endpoint the
    // quorum didn't.
    let (reply, seen) = serve(&mut core, 3, |request| {
        (request["params"]["endpoint"] == "d").then(|| rpc_result(r#""0x10""#))
    });
    // Whole milliseconds on the core's clock.
    assert!(started.elapsed() >= Duration::from_millis(499));
    let endpoints: Vec<&str> = seen
        .requests
        .iter()
        .map(|r| r["params"]["endpoint"].as_str().unwrap())
        .collect();
    assert_eq!(endpoints, ["a", "b", "c", "d"]);
    assert_eq!(
        reply["result"],
        json!({ "result": "0x10", "source": "direct", "verified": false, "undefined_keys": [], "generation": 1 })
    );
    // The members' exchanges were cancelled when they timed out.
    let mut members: Vec<u64> = seen.requests[..3]
        .iter()
        .map(|r| r["id"].as_u64().unwrap())
        .collect();
    let mut cancels = seen.cancels.clone();
    while cancels.len() < 3 {
        let message = core.recv();
        assert_eq!(message["type"], "cancel", "{message}");
        cancels.push(message["id"].as_u64().unwrap());
    }
    members.sort_unstable();
    cancels.sort_unstable();
    assert_eq!(cancels, members);
}

#[test]
fn colibri_faults_back_its_method_off_read_or_not() {
    // Two verifier faults back Colibri off a chain's method (design 0005,
    // Colibri: verifier faults), the second landing after its page's read
    // moved on to Direct; another method still goes to Colibri.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello_fragments();
    assert!(
        hello["result"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("colibri_faults")),
        "{hello}"
    );
    let mut chain = snapshot(&["colibri", "direct"], &["a"], 500);
    chain["prover"] = json!({ "endpoint": "p1", "zk": true });
    configure(&mut core, 2, &[chain]);
    let fault = json!({ "result": { "failure": "error", "fault": true } });
    let call_read = read("eth_call", json!([{ "to": ADDRESS }, "latest"]));
    core.send(&request(3, "chain.request", call_read.clone()));
    let (got, seen) = serve(&mut core, 3, |request| match request["method"].as_str() {
        Some("shell.verified") => Some(fault.clone()),
        _ => Some(rpc_result(r#""0x1""#)),
    });
    assert_eq!(got["result"]["source"], "direct", "{got}");
    assert_eq!(seen.requests[0]["method"], "shell.verified");
    // A page's read: Colibri's operation outlives the read's budget, and
    // its fault arrives once nobody reads it.
    let mut page = call_read.clone();
    page["origin"] = json!("https://app.example");
    core.send(&request(4, "chain.request", page));
    let mut held = None;
    let (got, _) = serve(&mut core, 4, |request| match request["method"].as_str() {
        Some("shell.verified") => {
            held = Some(request.clone());
            None
        }
        _ => Some(rpc_result(r#""0x1""#)),
    });
    assert_eq!(got["result"]["source"], "direct", "{got}");
    reply(&mut core, &held.unwrap(), fault);
    // Backed off: no operation, and Direct answers.
    core.send(&request(5, "chain.request", call_read));
    let (got, seen) = serve(&mut core, 5, |_| Some(rpc_result(r#""0x1""#)));
    assert_eq!(got["result"]["source"], "direct", "{got}");
    assert!(
        seen.requests.iter().all(|r| r["method"] == "shell.rpc"),
        "{:?}",
        seen.requests
    );
    core.send(&request(
        6,
        "chain.request",
        read("eth_getBalance", json!([ADDRESS, "latest"])),
    ));
    let (got, seen) = serve(&mut core, 6, |request| match request["method"].as_str() {
        Some("shell.verified") => Some(json!({ "result": { "result": "0x2" } })),
        _ => None,
    });
    assert_eq!(got["result"]["source"], "colibri", "{got}");
    assert_eq!(seen.requests.len(), 1);
}

#[test]
fn myotis_reads_through_shell_verified() {
    let (_root, mut core) = core();
    let mut chain = snapshot(&["myotis", "direct"], &["a"], 5000);
    chain["myotis"] = json!(true);
    configure(&mut core, 2, &[chain]);
    let ready = call(
        &mut core,
        3,
        "chain.availability",
        json!({ "chain_id": 1, "ready": true }),
    );
    assert_eq!(ready["result"], json!({}));
    let mut params = read("eth_getBalance", json!([ADDRESS, "latest"]));
    params["include_trust"] = json!(true);
    core.send(&request(4, "chain.request", params));
    let (reply, seen) = serve(&mut core, 4, |request| {
        assert_eq!(request["method"], "shell.verified");
        assert_eq!(
            request["params"],
            json!({ "myotis": "account", "chain_id": 1, "address": ADDRESS, "generation": 1 })
        );
        Some(json!({ "result": {
            "payload": { "verify_method": "proof", "balance_wei": "1000", "exists": true },
            "block_before": 21_000_000,
            "block_after": 21_000_000,
        } }))
    });
    assert_eq!(seen.requests.len(), 1);
    let result = &reply["result"];
    assert_eq!(result["result"], "0x3e8", "{reply}");
    assert_eq!(result["source"], "myotis");
    assert_eq!(result["verified"], true);
    assert!(result["trust"].is_object(), "{reply}");
    // A failure class falls through to Direct.
    core.send(&request(
        5,
        "chain.request",
        read("eth_getCode", json!([ADDRESS, "latest"])),
    ));
    let (reply, seen) = serve(&mut core, 5, |request| match request["method"].as_str() {
        Some("shell.verified") => Some(json!({ "result": { "failure": "queue_full" } })),
        _ => Some(rpc_result(r#""0x6001""#)),
    });
    assert_eq!(seen.requests[0]["params"]["myotis"], "code");
    assert_eq!(reply["result"]["result"], "0x6001");
    assert_eq!(reply["result"]["source"], "direct");
}

#[test]
fn a_fee_quote() {
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    core.send(&request(
        3,
        "chain.fee_quote",
        json!({ "chain_id": 1, "deadline_ms": 30_000 }),
    ));
    let (reply, seen) = serve(&mut core, 3, |request| {
        Some(match rpc_method(request).as_str() {
            "eth_gasPrice" => rpc_result(r#""0x3b9aca00""#),
            "eth_maxPriorityFeePerGas" => rpc_result(r#""0x5f5e100""#),
            other => panic!("{other}"),
        })
    });
    // Direct asks its one endpoint for both: B's quote from one answer.
    assert!(seen.requests.iter().all(|r| r["params"]["endpoint"] == "a"));
    assert_eq!(
        reply["result"],
        json!({
            "type": "eip1559",
            "baseFee": "900000000",
            "maxPriorityFeePerGas": "100000000",
            "maxFeePerGas": "1900000000",
            "effectiveGasPrice": "1000000000",
            "source": "direct",
            "verified": false,
            "answered": 1,
            "generation": 1,
        })
    );
}

fn broadcast(id: u64) -> Value {
    request(
        id,
        "chain.broadcast",
        json!({ "chain_id": 1, "raw": RAW, "deadline_ms": 60_000 }),
    )
}

/// The bytes an attempt sends: `eth_sendRawTransaction` of `RAW`.
fn sends_raw(request: &Value) -> bool {
    (request["method"] == "shell.rpc"
        && body(request)["method"] == "eth_sendRawTransaction"
        && body(request)["params"] == json!([RAW]))
        || (request["method"] == "shell.verified"
            && request["params"]["myotis"] == "broadcast"
            && request["params"]["raw"] == RAW)
}

#[test]
fn a_broadcast_is_sent_or_rejected() {
    let (_root, mut core) = core();
    let mut chain = snapshot(&["direct"], &["a", "b"], 5000);
    chain["myotis"] = json!(true);
    chain["broadcast_order"] = json!(["myotis", "direct"]);
    configure(&mut core, 2, &[chain]);
    call(
        &mut core,
        3,
        "chain.availability",
        json!({ "chain_id": 1, "ready": true }),
    );
    // Myotis sent nothing; the first endpoint refuses; the second accepts.
    core.send(&broadcast(4));
    let (reply, seen) = serve(&mut core, 4, |request| {
        assert!(sends_raw(request), "{request}");
        Some(
            match (
                request["method"].as_str(),
                request["params"]["endpoint"].as_str(),
            ) {
                (Some("shell.verified"), _) => json!({ "result": { "not_sent": true } }),
                (_, Some("a")) => rpc(
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
                ),
                _ => rpc_result(&format!("\"{HASH}\"")),
            },
        )
    });
    assert_eq!(seen.requests.len(), 3);
    assert_eq!(
        reply["result"],
        json!({ "hash": HASH, "source": "direct", "outcome": "sent", "generation": 1 })
    );
    // Every endpoint refuses: rejected, with the last refusal.
    core.send(&broadcast(5));
    let (reply, _) = serve(&mut core, 5, |request| {
        Some(match request["method"].as_str() {
            Some("shell.verified") => json!({ "result": { "not_sent": true } }),
            _ => rpc(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"insufficient funds for gas * price + value"}}"#,
            ),
        })
    });
    let error = &reply["error"];
    assert_eq!(error["code"], "chain_error", "{reply}");
    assert_eq!(
        error["data"],
        json!({
            "kind": "node",
            "constructor": "Error",
            "message": "insufficient funds for gas * price + value",
            "props": { "code": -32000, "data": null },
            "undefined_keys": ["data"],
            "outcome": "rejected",
            "generation": 1,
        })
    );
}

#[test]
fn a_myotis_refusal_keeps_its_code() {
    // The core offers the form with a code; main sends it to no other core.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello_fragments();
    assert!(
        hello["result"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("myotis_refusal_codes")),
        "{hello}"
    );
    let mut chain = snapshot(&["direct"], &["a"], 5000);
    chain["myotis"] = json!(true);
    chain["broadcast_order"] = json!(["myotis", "direct"]);
    configure(&mut core, 2, &[chain]);
    call(
        &mut core,
        3,
        "chain.availability",
        json!({ "chain_id": 1, "ready": true }),
    );
    // Either refusal ends the broadcast `rejected`, Direct never asked,
    // with the adapter's error: its message, code and marker.
    for (id, rejected, code, marker) in [
        (
            4,
            json!({ "reason": "nonce too low: next nonce 5, tx nonce 4" }),
            -32000,
            "rejected",
        ),
        (
            5,
            json!({
                "reason": "invalid raw transaction: malformed type 0x2 transaction",
                "code": -32602,
            }),
            -32602,
            "invalid-params",
        ),
    ] {
        core.send(&broadcast(id));
        let (reply, seen) = serve(&mut core, id, |request| {
            assert_eq!(request["method"], "shell.verified", "{request}");
            Some(json!({ "result": { "rejected": rejected.clone() } }))
        });
        assert_eq!(seen.requests.len(), 1);
        assert_eq!(reply["error"]["code"], "chain_error", "{reply}");
        assert_eq!(
            reply["error"]["data"],
            json!({
                "kind": "core",
                "constructor": "Error",
                "message": rejected["reason"],
                "props": { "code": code, "myotisRefusal": marker },
                "undefined_keys": [],
                "outcome": "rejected",
                "generation": 1,
            })
        );
    }
    // A code the closed set doesn't have is a malformed reply.
    core.send(&broadcast(6));
    malformed(
        &mut core,
        6,
        json!({ "result": { "rejected": { "reason": "x", "code": -32000 } } }),
        "malformed_shell_reply",
    );
}

#[test]
fn an_ambiguous_broadcast_is_reconciled() {
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    // The attempt's reply is lost; the lookup finds the transaction.
    core.send(&broadcast(3));
    let (reply, seen) = serve(&mut core, 3, |request| {
        Some(match rpc_method(request).as_str() {
            "eth_sendRawTransaction" => failure("network"),
            "eth_getTransactionByHash" => {
                assert_eq!(body(request)["params"], json!([HASH]));
                rpc_result(&format!(r#"{{"hash":"{HASH}","nonce":"0x0"}}"#))
            }
            other => panic!("{other}"),
        })
    });
    assert_eq!(seen.requests.len(), 2);
    assert_eq!(
        reply["result"],
        json!({ "hash": HASH, "source": "reconcile", "outcome": "sent", "generation": 1 })
    );
    // The network doesn't know it: uncertain, never a failure.
    core.send(&broadcast(4));
    let (reply, _) = serve(&mut core, 4, |request| {
        Some(match rpc_method(request).as_str() {
            "eth_sendRawTransaction" => failure("timeout"),
            _ => rpc_result("null"),
        })
    });
    assert_eq!(
        reply["result"],
        json!({ "hash": HASH, "source": "direct", "outcome": "uncertain", "generation": 1 })
    );
}

/// Main's record of a broadcast in flight (design 0005, Main's record):
/// marked when its executors start an exchange that sends the raw bytes.
#[derive(Default)]
struct Record {
    marked: bool,
}

impl Record {
    fn start(&mut self, request: &Value) {
        self.marked |= sends_raw(request);
    }

    /// Main's report when the core is lost without a reply: `uncertain` if
    /// marked, `not_sent` otherwise, never `rejected`.
    fn report(&self) -> &'static str {
        if self.marked { "uncertain" } else { "not_sent" }
    }
}

/// Kills the core: what it wrote before it died never answers `id`, and
/// main fences the dead core's requests, starting none of them.
fn lose(core: &mut Core, id: u64) {
    let _ = core.child.kill();
    for message in core.rest() {
        assert!(
            message["type"] != "response" || message["id"] != id,
            "{message}"
        );
    }
}

#[test]
fn main_reports_a_lost_core_from_its_record() {
    // The core dies after main started the attempt: uncertain.
    let (_first, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    core.send(&broadcast(3));
    let mut record = Record::default();
    let attempt = core.recv();
    assert!(sends_raw(&attempt), "{attempt}");
    record.start(&attempt);
    lose(&mut core, 3);
    assert_eq!(record.report(), "uncertain");
    // It dies before main starts anything: not sent, whatever it wrote.
    let (_second, mut core) = self::core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    core.send(&broadcast(3));
    let record = Record::default();
    lose(&mut core, 3);
    assert_eq!(record.report(), "not_sent");
}

#[test]
fn a_configuration_change_ends_the_chains_requests() {
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    core.send(&request(
        3,
        "chain.request",
        read("eth_blockNumber", json!([])),
    ));
    let held = core.recv();
    assert_eq!(held["params"]["generation"], 1);
    // The change: the read ends at once, under the generation it ran in,
    // before configure's own reply; its exchange is cancelled.
    core.send(&request(
        4,
        "chain.configure",
        json!({ "chains": [snapshot(&["direct"], &["b"], 5000)] }),
    ));
    let ended = core.recv();
    assert_eq!(ended["id"], 3, "{ended}");
    assert_eq!(
        ended["error"],
        json!({
            "code": "reconfigured",
            "message": "The chain's configuration changed",
            "data": { "generation": 1 },
        })
    );
    let configured = core.recv();
    assert_eq!(configured["id"], 4);
    assert_eq!(configured["result"], json!({ "generations": { "1": 2 } }));
    let cancel = core.recv();
    assert_eq!(cancel, json!({ "type": "cancel", "id": held["id"] }));
    // Main's not_sent for the stale exchange is dropped.
    reply(&mut core, &held, json!({ "result": { "not_sent": true } }));
    // Main sends the read again: it runs under the new generation.
    core.send(&request(
        5,
        "chain.request",
        read("eth_blockNumber", json!([])),
    ));
    let (reply, seen) = serve(&mut core, 5, |request| {
        assert_eq!(request["params"]["endpoint"], "b");
        assert_eq!(request["params"]["generation"], 2);
        Some(rpc_result(r#""0x2""#))
    });
    assert_eq!(seen.requests.len(), 1);
    assert_eq!(reply["result"]["generation"], 2);
}

#[test]
fn a_cancel_ends_a_read_and_its_exchanges() {
    let (_root, mut core) = core();
    configure(
        &mut core,
        2,
        &[snapshot(&["quorum"], &["a", "b", "c"], 5000)],
    );
    core.send(&request(
        3,
        "chain.request",
        read("eth_blockNumber", json!([])),
    ));
    let members: Vec<Value> = requests_only(&mut core, 3);
    core.send(&json!({ "type": "cancel", "id": 3 }));
    // The reply, and a cancel for every member, quorum members included
    // (deviation `abandoned-exchanges`).
    let mut cancels = Vec::new();
    let mut cancelled = None;
    while cancelled.is_none() || cancels.len() < 3 {
        let message = core.recv();
        match message["type"].as_str() {
            Some("cancel") => cancels.push(message["id"].clone()),
            Some("response") => cancelled = Some(message),
            _ => panic!("unexpected {message}"),
        }
    }
    let cancelled = cancelled.unwrap();
    assert_eq!(cancelled["id"], 3);
    assert_eq!(cancelled["error"]["code"], "cancelled", "{cancelled}");
    assert_eq!(cancelled["error"]["data"], json!({ "generation": 1 }));
    let asked: Vec<Value> = members.iter().map(|m| m["id"].clone()).collect();
    assert_eq!(cancels, asked);
    // Their terminal replies are still main's to send, and are dropped.
    for member in &members {
        reply(&mut core, member, failure("cancelled"));
    }
    assert!(call(&mut core, 1000, "vault.status", json!({}))["result"].is_object());
}

#[test]
fn the_overall_deadline() {
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 60_000)]);
    let mut params = read("eth_blockNumber", json!([]));
    params["deadline_ms"] = json!(300);
    let started = Instant::now();
    core.send(&request(3, "chain.request", params.clone()));
    let held = core.recv();
    // The exchange's own 60 s is capped by what is left of the read's
    // (design 0005, Deadlines).
    let left = held["params"]["deadline_ms"].as_u64().unwrap();
    assert!((1..=300).contains(&left), "{held}");
    // The exchange is cancelled and the read replies `deadline`.
    let first = core.recv();
    let elapsed = started.elapsed();
    let second = core.recv();
    let (reply, cancel) = if first["type"] == "cancel" {
        (second, first)
    } else {
        (first, second)
    };
    assert_eq!(reply["id"], 3, "{reply}");
    assert_eq!(reply["error"]["code"], "deadline");
    assert_eq!(reply["error"]["data"], json!({ "generation": 1 }));
    // The core's clock counts whole milliseconds: its 300 can be 299.x of
    // ours.
    assert!(elapsed >= Duration::from_millis(299), "{elapsed:?}");
    assert_eq!(cancel, json!({ "type": "cancel", "id": held["id"] }));
    // No time left: `deadline` before any I/O.
    params["deadline_ms"] = json!(0);
    let reply = call(&mut core, 4, "chain.request", params);
    assert_eq!(reply["error"]["code"], "deadline");
    assert_eq!(reply["error"]["data"]["generation"], 1);
    // Over 120 s is main's bug.
    let mut over = read("eth_blockNumber", json!([]));
    over["deadline_ms"] = json!(120_001);
    let reply = call(&mut core, 5, "chain.request", over);
    assert_eq!(reply["error"]["code"], "invalid_argument");
}

#[test]
fn admission_is_busy_past_64_running_and_256_waiting() {
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 60_000)]);
    for i in 0..321 {
        core.send(&request(
            10 + i,
            "chain.request",
            read("eth_blockNumber", json!([])),
        ));
    }
    // 64 run and ask main; 256 wait; the last is busy at once.
    let mut asked = 0;
    let busy = loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("request") => asked += 1,
            Some("response") => break message,
            _ => panic!("unexpected {message}"),
        }
    };
    assert_eq!(busy["id"], 10 + 320, "{busy}");
    assert_eq!(
        busy["error"],
        json!({ "code": "busy", "message": "Too many chain requests", "data": { "generation": 1 } })
    );
    while asked < 64 {
        let message = core.recv();
        assert_eq!(message["type"], "request", "{message}");
        asked += 1;
    }
    // The waiting requests start as running ones end; meanwhile the vault
    // answers.
    assert!(call(&mut core, 1000, "vault.status", json!({}))["result"].is_object());
}

/// Main answers the next `shell.rpc` with an `eth_call` result of `len`
/// hex digits, its reply fragmented (it is over one frame as base64), and
/// reads until both the core's reply to `id` and main's returned credit
/// have come.
fn large_answer(core: &mut Core, id: u64, len: usize) -> Vec<Wire> {
    let rpc = match core.recv_wire() {
        Wire::Message(message) if message["type"] == "request" => message,
        other => panic!("unexpected {other:?}"),
    };
    let text = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
        "ab".repeat(len / 2)
    );
    let response = json!({ "type": "response", "id": rpc["id"], "result": {
        "status": 200,
        "body": base64::engine::general_purpose::STANDARD.encode(&text),
    } });
    // Fragments of half a frame each.
    let pieces = response.to_string().len().div_ceil(MIB / 2);
    for frame in fragmented(&response, pieces) {
        core.send_raw(&frame);
    }
    let mut wires = Vec::new();
    let (mut replied, mut credit) = (false, false);
    while !(replied && credit) {
        let wire = core.recv_wire();
        replied |= matches!(&wire, Wire::Last(_))
            || matches!(&wire, Wire::Message(m) if m["type"] == "response" && m["id"] == id);
        credit |= wire == Wire::Credit;
        wires.push(wire);
    }
    wires
}

#[test]
fn a_large_answer_goes_out_in_fragments() {
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    core.send(&request(
        3,
        "chain.request",
        read("eth_call", json!([{ "to": ADDRESS }, "latest"])),
    ));
    // The core takes main's fragmented answer and returns its credit; its
    // own reply is fragmented.
    let wires = large_answer(&mut core, 3, 3 * MIB);
    let mut payload = Vec::new();
    let mut declared = None;
    for wire in &wires {
        match wire {
            Wire::Begin { id, bytes } => {
                assert_eq!(*id, 3);
                declared = Some(*bytes);
            }
            Wire::Fragment(bytes) | Wire::Last(bytes) => {
                assert!(bytes.len() <= MIB);
                payload.extend_from_slice(bytes);
            }
            _ => {}
        }
    }
    assert_eq!(Some(payload.len()), declared);
    let reply: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(reply["id"], 3);
    let result = &reply["result"];
    assert_eq!(result["result"].as_str().unwrap().len(), 3 * MIB + 2);
    assert_eq!(result["source"], "direct");
    assert_eq!(result["generation"], 1);
    // Main hands it over and returns the core's credit: the next large
    // reply may begin.
    core.send_credit();
    core.send(&request(
        4,
        "chain.request",
        read("eth_call", json!([{ "to": ADDRESS }, "latest"])),
    ));
    let wires = large_answer(&mut core, 4, 2 * MIB);
    assert!(matches!(
        wires.iter().find(|w| matches!(w, Wire::Begin { .. })),
        Some(Wire::Begin { id: 4, .. })
    ));
}

#[test]
fn too_large_without_fragments() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    // A main that takes no fragments; the core still takes main's.
    core.hello();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    core.send(&request(
        3,
        "chain.request",
        read("eth_call", json!([{ "to": ADDRESS }, "latest"])),
    ));
    let wires = large_answer(&mut core, 3, 2 * MIB);
    let reply = wires
        .iter()
        .find_map(|w| match w {
            Wire::Message(m) if m["type"] == "response" => Some(m.clone()),
            _ => None,
        })
        .unwrap();
    assert!(!wires.iter().any(|w| matches!(w, Wire::Begin { .. })));
    assert_eq!(reply["id"], 3);
    assert_eq!(
        reply["error"],
        json!({ "code": "too_large", "message": "Response too large", "data": { "generation": 1 } })
    );
}

#[test]
fn errors_take_their_wire_forms() {
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
    // A node's error passes through, tagged `node`.
    core.send(&request(
        3,
        "chain.request",
        read("eth_call", json!([{ "to": ADDRESS }, "latest"])),
    ));
    let (reply, _) = serve(&mut core, 3, |_| {
        Some(rpc(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":"0x08c379a0"}}"#,
        ))
    });
    assert_eq!(
        reply["error"],
        json!({
            "code": "chain_error",
            "message": "Chain request failed",
            "data": {
                "kind": "node",
                "constructor": "Error",
                "message": "execution reverted",
                "props": { "code": 3, "data": "0x08c379a0" },
                "undefined_keys": [],
                "generation": 1,
            },
        })
    );
    // The core's own texts, tagged `core`: before any I/O.
    let reply = call(&mut core, 4, "chain.request", read("eth_sign", json!([])));
    assert_eq!(reply["error"]["data"]["kind"], "core");
    assert_eq!(
        reply["error"]["data"]["message"],
        "Unsupported read method: eth_sign"
    );
    let mut unknown = read("eth_blockNumber", json!([]));
    unknown["chain_id"] = json!(5);
    let reply = call(&mut core, 5, "chain.request", unknown);
    assert_eq!(reply["error"]["data"]["message"], "Unsupported chain ID: 5");
    // A chain not configured has no generation yet.
    assert_eq!(reply["error"]["data"]["generation"], 0);
    // Every endpoint failing: the aggregate, with today's text.
    core.send(&request(
        6,
        "chain.request",
        read("eth_blockNumber", json!([])),
    ));
    let (reply, _) = serve(&mut core, 6, |_| Some(failure("network")));
    assert_eq!(reply["error"]["data"]["kind"], "core");
    assert_eq!(reply["error"]["data"]["constructor"], "TypeError");
    assert_eq!(reply["error"]["data"]["message"], "fetch failed");
    // Main's own mistakes: 0001's codes, no generation.
    let reply = call(&mut core, 7, "chain.request", json!({ "chain_id": 1 }));
    assert_eq!(
        reply["error"],
        json!({ "code": "invalid_argument", "message": "Invalid parameters" })
    );
}

#[test]
fn chain_and_naming_ids_interleave_in_one_increasing_space() {
    let (_root, mut core) = core();
    core.call(2, "naming.configure", common::naming_snapshot());
    configure(
        &mut core,
        3,
        &[snapshot(&["quorum"], &["c1", "c2", "c3"], 5000)],
    );
    let answers: BTreeMap<String, String> = common::naming_recorded();
    // Lookups (even IDs) and reads (odd ones), alternating.
    let mut pending: Vec<u64> = (10..16).collect();
    for i in 0..3u64 {
        core.send(&request(
            10 + 2 * i,
            "naming.resolve_content",
            json!({ "name": format!("n{i}.eth"), "private": false }),
        ));
        core.send(&request(
            11 + 2 * i,
            "chain.request",
            read("eth_blockNumber", json!([])),
        ));
    }
    let mut last = 0;
    let (mut naming, mut chain) = (0, 0);
    while !pending.is_empty() {
        let message = core.recv();
        match message["type"].as_str() {
            Some("request") => {
                let id = message["id"].as_u64().unwrap();
                // Main's reused_id rule: the core's IDs only increase.
                assert!(id > last, "{id} after {last}");
                last = id;
                if message["method"] == "shell.prefetch" {
                    reply(&mut core, &message, json!({ "result": {} }));
                } else if message["params"]["generations"].is_object() {
                    naming += 1;
                    let method = body(&message)["method"].as_str().unwrap().to_owned();
                    let text = &answers[&method];
                    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
                    reply(
                        &mut core,
                        &message,
                        json!({ "result": { "status": 200, "body": encoded } }),
                    );
                } else {
                    chain += 1;
                    assert_eq!(message["params"]["policy"], "plain");
                    reply(&mut core, &message, rpc_result(r#""0x5""#));
                }
            }
            Some("response") => {
                let id = message["id"].as_u64().unwrap();
                pending.retain(|p| *p != id);
                if id % 2 == 1 {
                    assert_eq!(message["result"]["result"], "0x5", "{message}");
                } else {
                    assert!(message["result"].is_object() || message["error"].is_object());
                }
            }
            Some("cancel") | Some("event") => {}
            _ => panic!("unexpected {message}"),
        }
    }
    assert!(naming > 0 && chain >= 6, "{naming} {chain}");
}

#[test]
fn main_holds_at_most_256_requests_across_naming_and_chain() {
    let (_root, mut core) = core();
    let mut many = common::naming_snapshot();
    many["rpc"] = (1..=64)
        .map(|i| json!({ "endpoint": format!("e{i}") }))
        .collect();
    core.call(2, "naming.configure", many);
    configure(&mut core, 3, &[snapshot(&["direct"], &["c1"], 60_000)]);
    // 32 lookups ask for far more than 256 head probes.
    for i in 0..32u64 {
        core.send(&request(
            100 + i,
            "naming.resolve_content",
            json!({ "name": format!("n{i}.eth"), "private": false }),
        ));
    }
    let mut outstanding: Vec<Value> = requests_only(&mut core, 256);
    // A read now finds no slot.
    core.send(&request(
        200,
        "chain.request",
        read("eth_blockNumber", json!([])),
    ));
    // Nothing more goes while main holds 256, the read's exchange
    // included: the vault's reply comes first.
    core.send(&request(201, "vault.status", json!({})));
    loop {
        let message = core.recv();
        assert_ne!(message["type"], "request", "{message}");
        if message["type"] == "response" && message["id"] == 201 {
            break;
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    // Each answer frees one slot, which goes to naming or to chain: the
    // read's exchange goes once it wins one.
    let read = loop {
        let probe = outstanding.remove(0);
        reply(&mut core, &probe, failure("network"));
        let next = loop {
            let message = core.recv();
            match message["type"].as_str() {
                Some("request") => break message,
                Some("cancel") | Some("response") => {}
                _ => panic!("unexpected {message}"),
            }
        };
        if next["params"]["policy"] == "plain" {
            break next;
        }
        outstanding.push(next);
    };
    assert_eq!(read["params"]["endpoint"], "c1");
    reply(&mut core, &read, rpc_result(r#""0x9""#));
    let answered = response_to(&mut core, 200);
    assert_eq!(answered["result"]["result"], "0x9", "{answered}");
}

// ---------------------------------------------------------------------------
// PR #57's reviews: each probe, through the real binary.

/// Main answers the core's next request with `outcome`, which is
/// malformed: the core ends the connection (exit 76, logging `category`)
/// and never replies to main's request `id`.
fn malformed(core: &mut Core, id: u64, outcome: Value, category: &str) {
    let request = requests_only(core, 1).pop().unwrap();
    reply(core, &request, outcome);
    let rest = core.rest();
    assert!(
        !rest
            .iter()
            .any(|m| m["type"] == "response" && m["id"] == id),
        "{rest:?}"
    );
    assert_eq!(core.exit_code(Duration::from_secs(10)), 76);
    let stderr = core.stderr();
    assert!(
        stderr.contains(&format!(r#""category":"{category}""#)),
        "{stderr}"
    );
}

/// A core with chain 1 configured as `chain`, Myotis ready if it serves
/// the chain.
fn configured(chain: Value) -> (tempfile::TempDir, Core) {
    let (root, mut core) = core();
    let myotis = chain["myotis"] == true;
    configure(&mut core, 2, &[chain]);
    if myotis {
        call(
            &mut core,
            3,
            "chain.availability",
            json!({ "chain_id": 1, "ready": true }),
        );
    }
    (root, core)
}

fn myotis_broadcaster() -> Value {
    let mut chain = snapshot(&[], &[], 5000);
    chain["myotis"] = json!(true);
    chain["broadcast_order"] = json!(["myotis"]);
    chain
}

#[test]
fn shell_errors_outside_the_transport_set_end_the_connection() {
    // Daemon review MEDIUM 1: request and protocol codes are no transport
    // failure; nor is one with data beside it.
    for (error, category) in [
        (
            json!({ "code": "invalid_argument", "message": "not a transport failure" }),
            "malformed_shell_reply",
        ),
        (
            json!({ "code": "internal", "message": "Internal error" }),
            "malformed_shell_reply",
        ),
        (
            json!({ "code": "unknown_method", "message": "Unknown method" }),
            "malformed_shell_reply",
        ),
        (
            json!({ "code": "network", "message": "Network error", "data": {} }),
            "malformed_shell_reply",
        ),
        // A member an error body doesn't have.
        (
            json!({ "code": "network", "message": "Network error", "unexpected": 1 }),
            "malformed_shell_reply",
        ),
    ] {
        let (_root, mut core) = configured(snapshot(&["direct"], &["a"], 5000));
        core.send(&request(
            4,
            "chain.request",
            read("eth_blockNumber", json!([])),
        ));
        malformed(&mut core, 4, json!({ "error": error }), category);
    }
}

#[test]
fn configure_requires_prover_and_blockscout_to_be_present() {
    // Daemon review MEDIUM 2: `null` when absent, but never missing.
    let (_root, mut core) = core();
    for (id, member) in [(2, "prover"), (3, "blockscout")] {
        let mut chain = snapshot(&["direct"], &["a"], 5000);
        chain.as_object_mut().unwrap().remove(member);
        let reply = call(
            &mut core,
            id,
            "chain.configure",
            json!({ "chains": [chain] }),
        );
        assert_eq!(reply["error"]["code"], "invalid_argument", "{member}");
    }
    let mut chain = snapshot(&["direct"], &["a"], 5000);
    chain["prover"] = json!({ "endpoint": "p1", "zk": false });
    assert_eq!(configure(&mut core, 4, &[chain]), json!({ "1": 1 }));
}

#[test]
fn arrays_are_never_proofs_that_nothing_was_sent() {
    // 57-M1: an array where an object belongs, outer or nested, is
    // malformed, and never lowers a broadcast's outcome.
    let direct = snapshot(&[], &["a"], 5000);
    let colibri = {
        let mut chain = snapshot(&["colibri"], &[], 5000);
        chain["prover"] = json!({ "endpoint": "p1", "zk": true });
        chain
    };
    let myotis_reader = {
        let mut chain = snapshot(&["myotis"], &[], 5000);
        chain["myotis"] = json!(true);
        chain
    };
    let call_read = read("eth_call", json!([{ "to": ADDRESS }, "latest"]));
    for (chain, call, result) in [
        // A Direct attempt: `[true]` for `{ not_sent: true }`.
        (direct.clone(), broadcast(4), json!([true])),
        (
            direct,
            broadcast(4),
            json!({ "status": 200, "body": ["e30="] }),
        ),
        // Myotis's broadcast: outer and nested arrays.
        (myotis_broadcaster(), broadcast(4), json!([true])),
        (
            myotis_broadcaster(),
            broadcast(4),
            json!({ "rejected": ["no"] }),
        ),
        (
            myotis_broadcaster(),
            broadcast(4),
            json!({ "rejected": { "reason": ["no"] } }),
        ),
        (myotis_broadcaster(), broadcast(4), json!(["0xab"])),
        // Verified reads.
        (
            myotis_reader,
            request(4, "chain.request", call_read.clone()),
            json!([{ "verify_method": "proof" }, 1, 1]),
        ),
        (
            colibri.clone(),
            request(4, "chain.request", call_read.clone()),
            json!({ "revert": ["0x12"] }),
        ),
        (
            colibri,
            request(4, "chain.request", call_read.clone()),
            json!([true]),
        ),
    ] {
        let (_root, mut core) = configured(chain);
        core.send(&call);
        malformed(
            &mut core,
            4,
            json!({ "result": result }),
            "malformed_shell_reply",
        );
    }
}

/// Fills main's 256 slots with naming's requests: four lookups over 64
/// endpoints, 64 head probes each. Returns the probes.
fn saturate_with_naming(core: &mut Core) -> Vec<Value> {
    let mut many = common::naming_snapshot();
    many["rpc"] = (1..=64)
        .map(|i| json!({ "endpoint": format!("e{i}") }))
        .collect();
    call(core, 2, "naming.configure", many);
    for i in 0..4u64 {
        core.send(&request(
            10 + i,
            "naming.resolve_content",
            json!({ "name": format!("n{i}.eth"), "private": false }),
        ));
    }
    requests_only(core, 256)
}

/// Main answers every naming request with a network error until the four
/// lookups have replied, so every slot is free again; whatever else the
/// core asks for meanwhile is returned.
fn drain_naming(core: &mut Core, probes: Vec<Value>) -> Vec<Value> {
    for probe in &probes {
        reply(core, probe, failure("network"));
    }
    let (mut lookups, mut other) = (0, Vec::new());
    while lookups < 4 {
        let message = core.recv();
        match message["type"].as_str() {
            Some("request") if message["params"]["generations"].is_object() => {
                reply(core, &message, failure("network"));
            }
            Some("request") => other.push(message),
            Some("response") if (10..14).contains(&message["id"].as_u64().unwrap()) => {
                lookups += 1;
            }
            _ => {}
        }
    }
    other
}

#[test]
fn a_cancelled_reads_queued_operation_never_starts() {
    // 57-M2: its operation waited for a slot; once its read has replied,
    // it never goes, and its Myotis slot is free.
    let (_root, mut core) = core();
    let probes = saturate_with_naming(&mut core);
    let mut chain = snapshot(&["myotis"], &[], 5000);
    chain["myotis"] = json!(true);
    configure(&mut core, 20, &[chain]);
    call(
        &mut core,
        21,
        "chain.availability",
        json!({ "chain_id": 1, "ready": true }),
    );
    let balance = read("eth_getBalance", json!([ADDRESS, "latest"]));
    core.send(&request(22, "chain.request", balance.clone()));
    core.send(&json!({ "type": "cancel", "id": 22 }));
    let cancelled = response_to(&mut core, 22);
    assert_eq!(cancelled["error"]["code"], "cancelled", "{cancelled}");
    let late = drain_naming(&mut core, probes);
    assert!(late.is_empty(), "after its reply: {late:?}");
    // The next read's operation goes: the slot was freed.
    core.send(&request(30, "chain.request", balance));
    let op = requests_only(&mut core, 1).pop().unwrap();
    assert_eq!(op["params"]["myotis"], "account", "{op}");
}

#[test]
fn a_broadcast_never_starts_after_its_attempt_cutoff() {
    // 57-M2: a Myotis broadcast still queued at its cutoff (200 ms here,
    // 10 s before its deadline) never starts: nothing was sent, and the
    // broadcast says so.
    let (_root, mut core) = core();
    let probes = saturate_with_naming(&mut core);
    configure(&mut core, 20, &[myotis_broadcaster()]);
    call(
        &mut core,
        21,
        "chain.availability",
        json!({ "chain_id": 1, "ready": true }),
    );
    let mut late = broadcast(22);
    late["params"]["deadline_ms"] = json!(10_200);
    core.send(&late);
    let ended = response_to(&mut core, 22);
    assert_eq!(ended["error"]["code"], "chain_error", "{ended}");
    assert_eq!(ended["error"]["data"]["outcome"], "not_sent");
    let after = drain_naming(&mut core, probes);
    assert!(
        !after.iter().any(sends_raw),
        "a broadcast after its cutoff: {after:?}"
    );
}

/// Main answers the core's next request, an `eth_call`, with a result of
/// `len` hex digits, in fragments; returns once the core has taken it and
/// returned main's credit. Whatever else comes meanwhile is returned.
fn answer_large(core: &mut Core, len: usize) -> Vec<Wire> {
    let mut seen = Vec::new();
    let rpc = loop {
        match core.recv_wire() {
            Wire::Message(message) if message["type"] == "request" => break message,
            other => seen.push(other),
        }
    };
    let text = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
        "ab".repeat(len / 2)
    );
    let response = json!({ "type": "response", "id": rpc["id"], "result": {
        "status": 200,
        "body": base64::engine::general_purpose::STANDARD.encode(&text),
    } });
    let pieces = response.to_string().len().div_ceil(MIB / 2);
    for frame in fragmented(&response, pieces) {
        core.send_raw(&frame);
    }
    loop {
        let wire = core.recv_wire();
        if wire == Wire::Credit {
            return seen;
        }
        seen.push(wire);
    }
}

#[test]
fn a_cancel_goes_while_bulk_replies_wait_for_credit() {
    // 57-M3: main withholds the core's bulk credit; the core's large
    // replies wait, filling its bulk share. A cancel and its small reply
    // still go at once.
    let (_root, mut core) = core();
    configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 60_000)]);
    core.send(&request(
        3,
        "chain.request",
        read("eth_blockNumber", json!([])),
    ));
    let running = requests_only(&mut core, 1).pop().unwrap();
    let call = read("eth_call", json!([{ "to": ADDRESS }, "latest"]));
    // The first large reply spends the core's credit, which main keeps.
    core.send(&request(4, "chain.request", call.clone()));
    let mut wires = answer_large(&mut core, 2 * MIB);
    while !wires.iter().any(|w| matches!(w, Wire::Last(_))) {
        wires.push(core.recv_wire());
    }
    // The next waits for credit in the writer, holding 16 MiB of the bulk
    // share; the one after can't fit beside it, and waits in the thread.
    core.send(&request(5, "chain.request", call.clone()));
    answer_large(&mut core, 16 * MIB);
    core.send(&request(6, "chain.request", call));
    answer_large(&mut core, 17 * MIB);
    std::thread::sleep(Duration::from_millis(200));
    core.send(&json!({ "type": "cancel", "id": 3 }));
    let mut prompt = Vec::new();
    while let Some(wire) = core.recv_wire_within(Duration::from_millis(500)) {
        prompt.push(wire);
    }
    assert!(
        prompt.contains(&Wire::Message(
            json!({ "type": "cancel", "id": running["id"] })
        )),
        "{prompt:?}"
    );
    let cancelled = prompt
        .iter()
        .find_map(|w| match w {
            Wire::Message(m) if m["type"] == "response" && m["id"] == 3 => Some(m.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no cancelled reply while credit is withheld: {prompt:?}"));
    assert_eq!(cancelled["error"]["code"], "cancelled");
    assert!(!prompt.iter().any(|w| matches!(w, Wire::Begin { .. })));
    // Credit back: the waiting replies go, one at a time.
    let mut begun = Vec::new();
    while begun.len() < 2 {
        core.send_credit();
        loop {
            match core.recv_wire() {
                Wire::Begin { id, .. } => begun.push(id),
                Wire::Last(_) => break,
                _ => {}
            }
        }
    }
    assert_eq!(begun, [5, 6]);
}

/// The core's resident memory and its peak, in KiB.
#[cfg(target_os = "linux")]
fn memory(core: &Core) -> (usize, usize) {
    let status = std::fs::read_to_string(format!("/proc/{}/status", core.child.id())).unwrap();
    let field = |name: &str| {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kib| kib.parse::<usize>().ok())
            .unwrap()
    };
    (field("VmRSS:"), field("VmHWM:"))
}

#[cfg(target_os = "linux")]
#[test]
fn reading_a_reply_reserves_before_it_allocates() {
    // 57-M4: with the chain total at 24 MiB (a debug-only hook), Myotis
    // refuses a broadcast with a 17 MiB reason. The message is charged as
    // it arrives; decoding its text would cross the total, so nothing is
    // decoded: the broadcast ends with its attempt possibly sent, and the
    // core's peak grows by the message alone, not the decoding's copies
    // (before the fix: the event loop's copy, an index, UTF-16 units and a
    // string, on top).
    let (_root, data, locks) = dirs();
    let mut core = common::spawn_env(
        "serve",
        &data,
        &locks,
        &[],
        &[("FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES", "25165824")],
    );
    core.hello_fragments();
    configure(&mut core, 2, &[myotis_broadcaster()]);
    call(
        &mut core,
        3,
        "chain.availability",
        json!({ "chain_id": 1, "ready": true }),
    );
    core.send(&broadcast(4));
    let op = requests_only(&mut core, 1).pop().unwrap();
    assert!(sends_raw(&op), "{op}");
    let refusal = json!({ "type": "response", "id": op["id"], "result": {
        "rejected": { "reason": "x".repeat(17 * MIB) },
    } });
    let pieces = refusal.to_string().len().div_ceil(MIB / 2);
    let frames = fragmented(&refusal, pieces);
    drop(refusal);
    let (before, _) = memory(&core);
    for frame in &frames {
        core.send_raw(frame);
    }
    let ended = response_to(&mut core, 4);
    let (_, peak) = memory(&core);
    assert_eq!(
        ended["result"],
        json!({ "hash": HASH, "source": "myotis", "outcome": "uncertain", "generation": 1 }),
        "{ended}"
    );
    let grown = peak.saturating_sub(before) / 1024;
    assert!(
        grown < 30,
        "the peak grew by {grown} MiB reading a 17 MiB reply"
    );
}

#[test]
fn a_handed_off_broadcast_stays_uncertain_however_it_ends() {
    // The safety review's control: once an attempt went to main, a cancel,
    // a configuration change or the deadline leaves the broadcast
    // uncertain, under the generation it ran in.
    for myotis in [false, true] {
        for end in ["cancel", "configure", "deadline"] {
            let mut chain = snapshot(&[], &["a"], 5000);
            if myotis {
                chain["myotis"] = json!(true);
                chain["broadcast_order"] = json!(["myotis"]);
            }
            let (_root, mut core) = configured(chain.clone());
            let mut send = broadcast(4);
            if end == "deadline" {
                send["params"]["deadline_ms"] = json!(10_200);
            }
            core.send(&send);
            let attempt = requests_only(&mut core, 1).pop().unwrap();
            assert!(sends_raw(&attempt), "{attempt}");
            match end {
                "cancel" => core.send(&json!({ "type": "cancel", "id": 4 })),
                "configure" => {
                    chain["display_name"] = json!("changed");
                    core.send(&request(5, "chain.configure", json!({ "chains": [chain] })));
                }
                _ => {}
            }
            let (ended, _) = serve(&mut core, 4, |request| {
                assert!(!sends_raw(request), "{request}");
                Some(rpc_result("null"))
            });
            assert_eq!(
                ended["result"]["outcome"], "uncertain",
                "{myotis}/{end}: {ended}"
            );
            assert_eq!(ended["result"]["generation"], 1);
        }
    }
}

#[test]
fn every_transport_failure_of_an_attempt_keeps_it_possibly_sent() {
    // The safety review's control: only not_sent proves nothing went.
    for code in [
        "cancelled",
        "stale_generation",
        "refused",
        "busy",
        "too_large",
        "deadline",
        "timeout",
        "network",
    ] {
        let (_root, mut core) = configured(snapshot(&["direct"], &["a"], 5000));
        core.send(&broadcast(3));
        let (ended, seen) = serve(&mut core, 3, |request| {
            Some(if sends_raw(request) {
                failure(code)
            } else {
                rpc_result("null")
            })
        });
        assert_eq!(ended["result"]["outcome"], "uncertain", "{code}: {ended}");
        assert_eq!(ended["result"]["generation"], 1);
        assert!(
            seen.requests
                .iter()
                .any(|r| rpc_method(r) == "eth_getTransactionByHash")
        );
    }
}

#[test]
fn myotis_broadcast_failure_classes_say_whether_it_was_sent() {
    // The safety review's control (design 0005, The rest): four classes
    // count as not sent, every other may have dispatched.
    for class in [
        "not_running",
        "not_ready",
        "queue_full",
        "queue_deadline",
        "state_changed",
        "caller_deadline",
        "too_large",
        "busy",
        "error",
    ] {
        let (_root, mut core) = configured(myotis_broadcaster());
        core.send(&broadcast(4));
        let (ended, _) = serve(&mut core, 4, |_| {
            Some(json!({ "result": { "failure": class } }))
        });
        if ["not_running", "not_ready", "queue_full", "queue_deadline"].contains(&class) {
            assert_eq!(
                ended["error"]["data"]["outcome"], "not_sent",
                "{class}: {ended}"
            );
            assert_eq!(ended["error"]["data"]["generation"], 1);
        } else {
            assert_eq!(ended["result"]["outcome"], "uncertain", "{class}: {ended}");
            assert_eq!(ended["result"]["generation"], 1);
        }
    }
}

#[test]
fn other_malformed_replies_to_an_attempt_end_the_connection() {
    // The safety review's control: bad base64, not_sent beside another
    // member, not_sent false.
    for result in [
        json!({ "status": 200, "body": "!" }),
        json!({ "not_sent": true, "status": 200 }),
        json!({ "not_sent": false }),
    ] {
        let (_root, mut core) = configured(snapshot(&["direct"], &["a"], 5000));
        core.send(&broadcast(3));
        malformed(
            &mut core,
            3,
            json!({ "result": result }),
            "malformed_shell_reply",
        );
    }
}

#[test]
fn naming_gets_a_slot_while_chain_holds_main_busy() {
    // The daemon review's fairness probe: chain fills main's 256 slots
    // (reads of nine members each); a naming lookup still gets one of the
    // slots answers free, rather than waiting behind chain's queue.
    let (_root, mut core) = core();
    let mut nine = snapshot(
        &["quorum"],
        &["c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"],
        60_000,
    );
    nine["quorum"] = json!({ "k": 9, "m": 9, "timeout_ms": 60_000 });
    call(&mut core, 2, "naming.configure", common::naming_snapshot());
    configure(&mut core, 3, &[nine]);
    for i in 0..64 {
        let mut params = read("eth_blockNumber", json!([]));
        params["deadline_ms"] = json!(120_000);
        core.send(&request(100 + i, "chain.request", params));
    }
    let mut outstanding = requests_only(&mut core, 256);
    assert!(outstanding.iter().all(|r| r["params"]["policy"] == "plain"));
    core.send(&request(
        500,
        "naming.resolve_content",
        json!({ "name": "vitalik.eth", "private": false }),
    ));
    let mut released = 0;
    loop {
        let held = outstanding.remove(0);
        reply(&mut core, &held, failure("network"));
        released += 1;
        let next = loop {
            let message = core.recv();
            if message["type"] == "request" {
                break message;
            }
        };
        if next["params"]["generations"].is_object() {
            break;
        }
        outstanding.push(next);
        assert!(
            released < 64,
            "naming waited behind {released} chain requests"
        );
    }
}

// ---------------------------------------------------------------------------
// PR #57's second round of reviews.

#[test]
fn a_null_member_of_another_shape_is_malformed() {
    // R2-M1: a member that belongs to another shape is there whatever its
    // value; `{ failure, uncertain: null }` is no standalone failure, and
    // never lowers a handed-off broadcast to not sent.
    let colibri = {
        let mut chain = snapshot(&["colibri"], &[], 5000);
        chain["prover"] = json!({ "endpoint": "p1", "zk": true });
        chain
    };
    let myotis_reader = {
        let mut chain = snapshot(&["myotis"], &[], 5000);
        chain["myotis"] = json!(true);
        chain
    };
    let call_read = request(
        4,
        "chain.request",
        read("eth_call", json!([{ "to": ADDRESS }, "latest"])),
    );
    let mut cases = Vec::new();
    for extra in [
        "uncertain",
        "rejected",
        "revert",
        "block_before",
        "block_after",
        "hash",
        "result",
        "payload",
        "not_sent",
    ] {
        let mut shape = json!({ "failure": "not_running" });
        shape[extra] = Value::Null;
        cases.push((myotis_broadcaster(), broadcast(4), shape));
    }
    for shape in [
        json!({ "hash": HASH, "rejected": null }),
        json!({ "rejected": null }),
        json!({ "uncertain": null }),
    ] {
        cases.push((myotis_broadcaster(), broadcast(4), shape));
    }
    for shape in [
        json!({ "failure": "error", "payload": null }),
        json!({ "failure": "not_ready", "block_before": null }),
        json!({ "payload": { "verify_method": "proof" }, "hash": null }),
    ] {
        cases.push((myotis_reader.clone(), call_read.clone(), shape));
    }
    for shape in [
        json!({ "failure": "capacity", "revert": null }),
        json!({ "result": "0x01", "revert": null }),
        json!({ "revert": null }),
    ] {
        cases.push((colibri.clone(), call_read.clone(), shape));
    }
    for (chain, call, shape) in cases {
        let (_root, mut core) = configured(chain);
        core.send(&call);
        malformed(
            &mut core,
            4,
            json!({ "result": shape }),
            "malformed_shell_reply",
        );
    }
}

#[test]
fn a_shell_errors_message_counts_against_its_request() {
    // Round 2, daemon review: an error is charged before it is read, like
    // a result: with the chain total at 512 KiB, a 900 KB `network`
    // message ends its read with `budget`, a short one as today's error.
    for (message, code) in [
        ("x".to_owned(), "chain_error"),
        ("x".repeat(900_000), "budget"),
    ] {
        let (_root, data, locks) = dirs();
        let mut core = common::spawn_env(
            "serve",
            &data,
            &locks,
            &[],
            &[("FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES", "524288")],
        );
        core.hello_fragments();
        configure(&mut core, 2, &[snapshot(&["direct"], &["a"], 5000)]);
        core.send(&request(
            3,
            "chain.request",
            read("eth_blockNumber", json!([])),
        ));
        let (reply, _) = serve(&mut core, 3, |_| {
            Some(json!({ "error": { "code": "network", "message": message } }))
        });
        assert_eq!(reply["error"]["code"], code, "{reply}");
    }
}

/// Plays main for the replay's `ant-index-first-wallet-scan` (design 0005,
/// Logs: Blockscout pairing), a core started with `env`: its recorded
/// answers for every `shell.rpc` of its first call, and of its second up
/// to its first `shell.blockscout`. Returns the core, that request, and
/// the page main's recorded hop answered.
fn blockscout_scan_to(env: &[(&str, &str)]) -> (tempfile::TempDir, Core, Value, Value) {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/chain-replay.json"
    ))
    .unwrap();
    let vectors: Value = serde_json::from_str(&text).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "ant-index-first-wallet-scan")
        .unwrap()
        .clone();
    let records = scenario["io"].as_array().unwrap();
    let hop = records.iter().find(|r| r["kind"] == "blockscout").unwrap()["answer"].clone();
    let urls = [
        "https://gnosischain.example",
        "https://publicnode.example",
        "https://drpc.example",
    ];
    let mut chain = snapshot(&["quorum", "direct"], &urls, 5000);
    chain["chain_id"] = json!(100);
    chain["display_name"] = json!("Gnosis");
    chain["blockscout"] = json!({ "endpoint": "https://gnosis.blockscout.com/api" });
    let (root, data, locks) = dirs();
    let mut core = common::spawn_env("serve", &data, &locks, &[], env);
    core.hello_fragments();
    configure(&mut core, 2, &[chain]);
    for index in 0..2u64 {
        let call = &scenario["steps"][0]["calls"][index as usize];
        let params: Value = serde_json::from_str(call["params_json"].as_str().unwrap()).unwrap();
        let mut scan = read("eth_getLogs", params);
        scan["chain_id"] = json!(100);
        scan["background"] = json!(true);
        scan["profile"] = json!("ant_scan");
        let id = 3 + index;
        core.send(&request(id, "chain.request", scan));
        loop {
            let message = core.recv();
            if message["type"] == "response" && message["id"] == id {
                break;
            }
            if message["type"] != "request" {
                continue;
            }
            if message["method"] == "shell.blockscout" {
                return (root, core, message, hop);
            }
            let sent = body(&message);
            let record = records
                .iter()
                .find(|r| {
                    r["kind"] == "rpc"
                        && r["call"] == index
                        && r["url"] == message["params"]["endpoint"]
                        && serde_json::from_str::<Value>(r["body"].as_str().unwrap()).unwrap()
                            ["params"]
                            == sent["params"]
                })
                .unwrap();
            let answer = &record["answer"];
            reply(
                &mut core,
                &message,
                json!({ "result": {
                    "status": answer["status"],
                    "body": base64::engine::general_purpose::STANDARD
                        .encode(answer["body"].as_str().unwrap()),
                } }),
            );
        }
    }
    panic!("the scan never reached Blockscout");
}

/// As [`blockscout_scan_to`], main answering the page with `page` (from
/// the recorded hop) and the rest of the scan from the recordings: the
/// core, and its reply to the scan's second call, `None` once a malformed
/// page ended the connection.
fn blockscout_scan(page: impl Fn(&Value) -> Value) -> (tempfile::TempDir, Core, Option<Value>) {
    let (root, mut core, request, hop) = blockscout_scan_to(&[]);
    let answer = page(&hop);
    let malformed = answer["result"]["headers"]
        .as_object()
        .is_some_and(|h| h.len() > 8);
    reply(&mut core, &request, answer);
    if malformed {
        return (root, core, None);
    }
    // The rest of the second call: its Direct and quorum reads of the
    // newest blocks, from the recordings.
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/chain-replay.json"
    ))
    .unwrap();
    let vectors: Value = serde_json::from_str(&text).unwrap();
    let records = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "ant-index-first-wallet-scan")
        .unwrap()["io"]
        .as_array()
        .unwrap()
        .clone();
    loop {
        let message = core.recv();
        if message["type"] == "response" && message["id"] == 4 {
            return (root, core, Some(message));
        }
        if message["type"] != "request" {
            continue;
        }
        let sent = body(&message);
        let record = records
            .iter()
            .find(|r| {
                r["kind"] == "rpc"
                    && r["call"] == 1
                    && r["url"] == message["params"]["endpoint"]
                    && serde_json::from_str::<Value>(r["body"].as_str().unwrap()).unwrap()["params"]
                        == sent["params"]
            })
            .unwrap();
        let answer = &record["answer"];
        reply(
            &mut core,
            &message,
            json!({ "result": {
                "status": answer["status"],
                "body": base64::engine::general_purpose::STANDARD
                    .encode(answer["body"].as_str().unwrap()),
            } }),
        );
    }
}

/// Main's reply to a Blockscout page: the recorded hop, with `headers`.
fn page_with(hop: &Value, headers: Value) -> Value {
    json!({ "result": {
        "status": hop["status"],
        "headers": headers,
        "body": base64::engine::general_purpose::STANDARD.encode(hop["body"].as_str().unwrap()),
    } })
}

#[test]
fn a_blockscout_page_carries_a_few_headers() {
    // R2-M3, through the replay's Ant scan: the recorded page, with the
    // headers the core reads and a few it doesn't, is read and paired.
    let (_root, _core, reply) = blockscout_scan(|hop| {
        page_with(
            hop,
            json!({
                "content-type": "application/json",
                "Content-Length": "100000",
                "x-ratelimit-reset": "1000",
                "Retry-After": "1",
                "date": "Tue, 13 Oct 2026 06:00:00 GMT",
            }),
        )
    });
    let reply = reply.unwrap();
    assert!(reply["result"]["result"].is_array(), "{reply}");
    // Many more headers than a page needs are a malformed reply, refused
    // before anything of them is allocated: 200,000 empty ones (the
    // reviewer's probe) as well as nine.
    for count in [9usize, 200_000] {
        let headers: serde_json::Map<String, Value> = (0..count)
            .map(|i| (format!("x{i:06}"), json!("")))
            .collect();
        let headers = Value::Object(headers);
        let (_root, mut core, reply) = blockscout_scan(|hop| page_with(hop, headers.clone()));
        assert!(reply.is_none());
        let rest = core.rest();
        assert!(
            !rest.iter().any(|m| m["type"] == "response" && m["id"] == 4),
            "{count}"
        );
        assert_eq!(core.exit_code(Duration::from_secs(10)), 76);
        assert!(
            core.stderr()
                .contains(r#""category":"malformed_shell_reply""#)
        );
    }
}

/// The core's next message that isn't a returned credit.
fn next_message(core: &mut Core) -> Value {
    loop {
        match core.recv_wire() {
            Wire::Credit => {}
            Wire::Message(message) => return message,
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_page_is_checked_without_unescaping_anything_first() {
    // Round 3, R3-M2: with the chain total at 4 MiB, the scan's page comes
    // with one unknown header of 16 MiB of JSON: 8 Mi escaped backslashes,
    // or (the control) 16 Mi letters. The reply is charged before any of
    // it is parsed, and its check unescapes nothing: both end the scan with
    // `budget`, and the escaped one costs the core no more than the plain
    // one (before the fix, serde_json's scratch took 8 MiB more).
    let mut grown = Vec::new();
    for escaped in [false, true] {
        let (_root, mut core, page, _) =
            blockscout_scan_to(&[("FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES", "4194304")]);
        let value = if escaped {
            "\\".repeat(8 * MIB)
        } else {
            "x".repeat(16 * MIB)
        };
        let answer = json!({ "result": {
            "status": 200,
            "headers": { "x": value },
            "body": "",
        } });
        let (before, _) = memory(&core);
        reply(&mut core, &page, answer);
        let ended = loop {
            let message = next_message(&mut core);
            if message["type"] == "response" && message["id"] == 4 {
                break message;
            }
        };
        let (_, peak) = memory(&core);
        assert_eq!(ended["error"]["code"], "budget", "{escaped}: {ended}");
        grown.push(peak.saturating_sub(before) / 1024);
    }
    let (plain, escaped) = (grown[0], grown[1]);
    assert!(
        escaped <= plain + 4,
        "the escaped header cost {escaped} MiB, the plain one {plain} MiB"
    );
}

#[test]
fn the_endpoint_bound_counts_entries_before_repeats_merge() {
    let (_root, mut core) = core();
    let repeated = |n: usize| {
        let mut chain = snapshot(&["quorum"], &[], 5_000);
        chain["rpc"] = json!(vec![
            json!({ "endpoint": "a", "user_configured": false });
            n
        ]);
        chain
    };
    // 64 entries, all one endpoint: admitted, and merged to one.
    configure(&mut core, 2, &[repeated(64)]);
    // A 65th entry is refused at the wire bound, though it repeats an earlier one.
    let reply = call(
        &mut core,
        3,
        "chain.configure",
        json!({ "chains": [repeated(65)] }),
    );
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
}
