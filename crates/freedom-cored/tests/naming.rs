//! `naming.*` end to end (design 0004): the core resolves through main's
//! `shell.*` executors, played here from what the `quorum-agree` replay
//! scenario recorded for each JSON-RPC method.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use base64::Engine as _;
use common::{dirs, request, spawn};
use serde_json::{Value, json};

/// The answer body `quorum-agree` recorded for each method.
fn recorded() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/naming-replay.json"
    ))
    .unwrap();
    let vectors: Value = serde_json::from_str(&text).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "quorum-agree")
        .unwrap();
    let mut answers = BTreeMap::new();
    for exchange in scenario["io"].as_array().unwrap() {
        if let (Some(method), Some(body)) = (
            exchange["method"].as_str(),
            exchange["answer"]["body"].as_str(),
        ) {
            answers
                .entry(method.to_owned())
                .or_insert_with(|| body.to_owned());
        }
    }
    answers
}

fn snapshot() -> Value {
    json!({
        "reset": "none",
        "rpc": [{ "endpoint": "e1" }, { "endpoint": "e2" }, { "endpoint": "e3" }, { "endpoint": "e4" }],
        "direct": null,
        "prover": null,
        "policy": { "order": ["quorum"], "prefer_verified": false },
        "quorum": { "k": 3, "m": 2, "timeout_ms": 5000, "anchor": "latest", "anchor_ttl_ms": 30000 },
        "myotis_enabled": false,
        "tezos": ["t1", "t2", "t3"],
    })
}

/// Plays main until the response to `id`: answers every `shell.rpc` from
/// the recordings and counts the requests it saw.
fn serve_until(
    core: &mut common::Core,
    id: u64,
    answers: &BTreeMap<String, String>,
) -> (Value, usize) {
    let mut served = 0;
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            // The agreed answer's prefetch: main runs it on its own timer.
            Some("request") if message["method"] == "shell.prefetch" => {
                assert_eq!(
                    message["params"]["uri"],
                    "ipfs://QmW81r84Aihiqqi2Jw6nM1LnpeMfRCenRxtjwHNkXVkZYa"
                );
            }
            Some("request") => {
                assert_eq!(message["method"], "shell.rpc", "{message}");
                let params = &message["params"];
                assert!(params["endpoint"].as_str().unwrap().starts_with('e'));
                assert_eq!(params["generations"], json!({ "ens": 1 }));
                let body: Value = serde_json::from_str(params["body"].as_str().unwrap()).unwrap();
                let answer = &answers[body["method"].as_str().unwrap()];
                let encoded = base64::engine::general_purpose::STANDARD.encode(answer);
                core.send(&json!({
                    "type": "response",
                    "id": message["id"],
                    "result": { "status": 200, "body": encoded },
                }));
                served += 1;
            }
            // Main's IDs and the core's are separate spaces.
            Some("response") if message["id"] == id => return (message, served),
            Some("cancel") => {}
            _ => panic!("unexpected {message}"),
        }
    }
}

#[test]
fn resolves_content_through_main() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    // From the empty snapshot, both parts change.
    let configured = core.call(2, "naming.configure", snapshot());
    assert_eq!(configured["result"], json!({ "ens": 1, "tezos": 1 }));
    // The same snapshot again changes nothing.
    let again = core.call(20, "naming.configure", snapshot());
    assert_eq!(again["result"], json!({ "ens": 1, "tezos": 1 }));
    let answers = recorded();

    core.send(&request(
        30,
        "naming.resolve_content",
        json!({ "name": "vitalik.eth", "private": false }),
    ));
    let (reply, served) = serve_until(&mut core, 30, &answers);
    assert!(served >= 7, "anchor and legs went through main: {served}");
    let result = &reply["result"];
    assert_eq!(result["result"]["type"], "ok", "{reply}");
    assert_eq!(
        result["result"]["uri"],
        "ipfs://QmW81r84Aihiqqi2Jw6nM1LnpeMfRCenRxtjwHNkXVkZYa"
    );
    // Endpoints come back as references for main to substitute.
    let agreed = result["result"]["trust"]["agreed"].as_array().unwrap();
    assert!(
        agreed
            .iter()
            .all(|r| r["ref"].as_str().unwrap().starts_with('e'))
    );
    assert_eq!(result["undefined_keys"], json!([]));
    assert_eq!(
        result["generations"],
        json!({ "ens": 1, "tezos": 1, "lifecycle": 0 })
    );
    assert_eq!(result["attempts"], 1);

    // The second lookup is a cache hit: no I/O, no attempt.
    let hit = core.call(
        40,
        "naming.resolve_content",
        json!({ "name": "vitalik.eth", "private": true }),
    );
    assert_eq!(hit["result"]["result"]["type"], "ok");
    assert_eq!(hit["result"]["attempts"], 0);

    let evicted = core.call(
        50,
        "naming.invalidate_content",
        json!({ "name": "vitalik.eth" }),
    );
    assert_eq!(evicted["result"], json!({ "evicted": true }));
    let availability = core.call(
        60,
        "naming.availability",
        json!({ "ready": false, "enabled": false }),
    );
    assert_eq!(availability["result"], json!({ "lifecycle": 1 }));
    // The vault still answers while naming is configured.
    let status = core.call(70, "vault.status", json!({}));
    assert!(status["result"].is_object(), "{status}");
}

#[test]
fn a_cancelled_resolution_replies_cancelled() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(2, "naming.configure", snapshot());
    core.send(&request(
        30,
        "naming.resolve_content",
        json!({ "name": "vitalik.eth" }),
    ));
    // The core asks main for the anchor first.
    let first = core.recv();
    assert_eq!(first["method"], "shell.rpc", "{first}");
    core.send(&json!({ "type": "cancel", "id": 30 }));
    let reply = loop {
        let message = core.recv();
        if message["type"] == "response" {
            break message;
        }
    };
    assert_eq!(reply["id"], 30);
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
}

#[test]
fn errors_are_typed() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let invalid = core.call(2, "naming.configure", json!({ "rpc": "nope" }));
    assert_eq!(invalid["error"]["code"], "invalid_argument");
    core.call(3, "naming.configure", snapshot());
    // A thrown resolution, with today's message.
    let thrown = core.call(4, "naming.resolve_content", json!({ "name": "  " }));
    assert_eq!(thrown["error"]["code"], "resolution_failed", "{thrown}");
    assert_eq!(thrown["error"]["data"]["message"], "ENS name is empty");
    assert_eq!(thrown["error"]["data"]["attempts"], 0);
}

#[test]
fn an_unsolicited_shell_response_ends_the_core() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.send(&json!({ "type": "response", "id": 77, "result": {} }));
    // Exit::Protocol.
    assert_eq!(core.exit_code(std::time::Duration::from_secs(10)), 76);
}

#[test]
fn a_burst_while_main_is_not_reading_backs_up_rather_than_exiting() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let mut many = snapshot();
    many["rpc"] = (1..=64)
        .map(|i| json!({ "endpoint": format!("e{i}") }))
        .collect();
    core.call(2, "naming.configure", many);
    // Main stalls: 2,048 lookups and then a vault request arrive while it
    // reads nothing. The core's shell requests and busy replies back up
    // behind the pipe, far past what it holds.
    core.pause_reading();
    for i in 0..2048u64 {
        core.send(&request(
            100 + i,
            "naming.resolve_content",
            json!({ "name": format!("n{i}.eth"), "private": false }),
        ));
    }
    core.send(&request(10_000, "vault.status", json!({})));
    std::thread::sleep(std::time::Duration::from_millis(500));
    core.resume_reading();
    // Reading again, the vault's reply arrives (its share of the writer
    // is its own) and every lookup was taken in.
    let (mut status, mut busy, mut shell) = (false, 0, 0);
    while !(status && busy == 2048 - 32 && shell == 256) {
        let message = core.recv();
        match (message["type"].as_str(), message["id"].as_u64()) {
            (Some("response"), Some(10_000)) => {
                assert!(message["result"].is_object(), "{message}");
                status = true;
            }
            (Some("response"), _) if message["error"]["code"] == "busy" => busy += 1,
            (Some("request"), _) => shell += 1,
            // Unanswered, the probes time out and are cancelled.
            _ => {}
        }
    }
    // The core is alive.
    assert!(core.call(10_001, "vault.status", json!({}))["result"].is_object());
}

#[test]
fn an_error_that_echoes_a_huge_name_still_fits_a_frame() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    // Without a configuration the lookup fails at once, with a message
    // that echoes the name: nearly a whole frame of it.
    let name = format!("{}.eth", "a".repeat(1_040_000));
    core.send(&request(
        2,
        "naming.resolve_content",
        json!({ "name": name, "private": false }),
    ));
    let reply = core.until_response(2);
    assert_eq!(reply["error"]["code"], "resolution_failed", "{reply}");
    assert_eq!(reply["error"]["data"]["message"], "result too large");
    assert!(core.call(3, "vault.status", json!({}))["result"].is_object());
}
