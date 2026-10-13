//! `naming.*` end to end (design 0004): the core resolves through main's
//! `shell.*` executors, played here from what the `quorum-agree` replay
//! scenario recorded for each JSON-RPC method.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::{
    dirs, naming_recorded as recorded, naming_snapshot as snapshot, request, spawn, spawn_env,
};
use serde_json::{Value, json};

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
    assert_eq!(
        configured["result"],
        json!({ "ens": 1, "tezos": 1, "lifecycle": 0 })
    );
    // The same snapshot again changes nothing.
    let again = core.call(20, "naming.configure", snapshot());
    assert_eq!(
        again["result"],
        json!({ "ens": 1, "tezos": 1, "lifecycle": 0 })
    );
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
    let (root, data, locks) = dirs();
    let marker = root.path().join("naming-marks");
    let marker_path = marker.display().to_string();
    let mut core = spawn_env(
        "serve",
        &data,
        &locks,
        &[],
        &[("FREEDOM_CORED_TEST_NAMING_MARKER", &marker_path)],
    );
    core.hello();
    let mut many = snapshot();
    many["rpc"] = (1..=64)
        .map(|i| json!({ "endpoint": format!("e{i}") }))
        .collect();
    // No probe times out while the test runs (sessions end at 120 s
    // anyway), so the 32 sessions admitted first keep running however
    // long the burst takes to arrive. With 5 s, a burst slower than that
    // outlived them: their timeouts freed admission and quarantined every
    // endpoint, and later lookups failed at once instead of being busy.
    many["quorum"]["timeout_ms"] = json!(600_000);
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
    // Main reads again once the naming thread has made every busy reply
    // (and, before them, the configure reply).
    wait_for_marks(&marker, "made the busy replies", |marks| {
        marks.iter().filter(|mark| *mark == "reply").count() >= 1 + 2048 - 32
    });
    core.resume_reading();
    // Reading again, the vault's reply arrives (its share of the writer
    // is its own) and every lookup was taken in: the first 32 run, with
    // main holding 256 of their probes (its limit), and every later one is
    // busy, once.
    let mut busy = BTreeSet::new();
    let (mut status, mut shell) = (false, 0);
    while !(status && busy.len() == 2048 - 32 && shell == 256) {
        let message = core.recv();
        match (message["type"].as_str(), message["id"].as_u64()) {
            (Some("response"), Some(10_000)) => {
                assert!(message["result"].is_object(), "{message}");
                status = true;
            }
            (Some("response"), Some(id @ 132..2148)) if message["error"]["code"] == "busy" => {
                assert!(busy.insert(id), "a second reply: {message}");
            }
            (Some("request"), _) => {
                assert_eq!(message["method"], "shell.rpc", "{message}");
                shell += 1;
                assert!(shell <= 256, "past main's limit: {message}");
            }
            _ => panic!("unexpected {message}"),
        }
    }
    // The core is alive, and nothing else came meanwhile.
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

/// The lines the naming thread has appended to its marker so far
/// (`FREEDOM_CORED_TEST_NAMING_MARKER`), whole lines only.
fn naming_marks(marker: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(marker).unwrap_or_default();
    text.split_inclusive('\n')
        .filter_map(|line| line.strip_suffix('\n'))
        .map(str::to_owned)
        .collect()
}

/// Waits until the naming thread's marks show `what`, and returns them.
fn wait_for_marks(marker: &Path, what: &str, done: impl Fn(&[String]) -> bool) -> Vec<String> {
    let deadline = Instant::now() + common::READ_TIMEOUT;
    loop {
        let marks = naming_marks(marker);
        if done(&marks) {
            return marks;
        }
        assert!(Instant::now() < deadline, "never {what}: {marks:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn replies_waiting_for_the_writer_survive_shutdown() {
    let (root, data, locks) = dirs();
    let marker = root.path().join("naming-marks");
    let marker_path = marker.display().to_string();
    let mut core = spawn_env(
        "serve",
        &data,
        &locks,
        &[],
        &[("FREEDOM_CORED_TEST_NAMING_MARKER", &marker_path)],
    );
    core.hello();
    // Main stalls while 16 lookups fail at once, each reply carrying a
    // 600 KB name: more than naming's 8 MiB share, so some wait in the
    // naming thread when shutdown comes.
    core.pause_reading();
    for i in 0..16u64 {
        let name = format!("{}{i}.eth", "a".repeat(600_000));
        core.send(&request(
            10 + i,
            "naming.resolve_content",
            json!({ "name": name, "private": false }),
        ));
    }
    // Long names take a while to normalize: seconds for the 16, in a debug
    // build under load. Shutdown comes once the naming thread has made all
    // 16 replies. (A lookup still running at shutdown may get no reply, as
    // 0001's drain is bounded, which this test isn't about.)
    wait_for_marks(&marker, "made 16 replies", |marks| {
        marks.iter().filter(|mark| *mark == "reply").count() >= 16
    });
    core.send(&request(100, "core.shutdown", json!({})));
    // Main reads again only after shutdown has ended the naming thread,
    // which hands the replies still waiting in it to the writer.
    let marks = wait_for_marks(&marker, "drained", |marks| {
        marks.iter().any(|mark| mark.starts_with("drain "))
    });
    let drained: usize = marks
        .iter()
        .find_map(|mark| mark.strip_prefix("drain "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        drained > 0,
        "no reply waited in the naming thread: {marks:?}"
    );
    core.resume_reading();
    let (mut replies, mut shutdown) = (0, false);
    while !(shutdown && replies == 16) {
        let message = core.recv();
        match message["id"].as_u64() {
            Some(100) => shutdown = true,
            Some(10..26) => replies += 1,
            _ => panic!("unexpected {message}"),
        }
    }
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn a_verified_request_too_large_to_send_settles_in_the_core() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let mut myotis = snapshot();
    myotis["policy"]["order"] = json!(["myotis"]);
    myotis["myotis_enabled"] = json!(true);
    core.call(2, "naming.configure", myotis);
    core.call(
        3,
        "naming.availability",
        json!({ "ready": true, "enabled": true }),
    );
    // The largest lookup main can send: its verified operation, in a
    // longer envelope, can't fit a frame.
    let empty = request(
        4,
        "naming.resolve_content",
        json!({ "name": "", "private": false }),
    );
    let room = (1 << 20) - empty.to_string().len() - ".eth".len();
    let name = format!("{}.eth", "a".repeat(room));
    let lookup = request(
        4,
        "naming.resolve_content",
        json!({ "name": name, "private": false }),
    );
    assert_eq!(lookup.to_string().len(), 1 << 20);
    core.send(&lookup);
    let reply = core.until_response(4);
    assert_eq!(reply["error"]["code"], "resolution_failed", "{reply}");
    assert!(core.call(5, "vault.status", json!({}))["result"].is_object());
}

#[test]
fn no_shell_request_follows_the_shutdown_reply() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let mut many = snapshot();
    many["rpc"] = (1..=64)
        .map(|i| json!({ "endpoint": format!("e{i}") }))
        .collect();
    core.call(2, "naming.configure", many);
    for i in 0..32u64 {
        core.send(&request(
            100 + i,
            "naming.resolve_content",
            json!({ "name": format!("n{i}.eth"), "private": false }),
        ));
    }
    // The first 256 probes, at the outstanding cap; more wait their turn.
    let mut first = None;
    let mut seen = 0;
    while seen < 256 {
        let message = core.recv();
        if message["type"] == "request" {
            first.get_or_insert(message["id"].clone());
            seen += 1;
        }
    }
    // In one write: a slow naming request, an answer that frees a slot,
    // and shutdown. The freed slot must not admit a waiting probe after
    // the shutdown reply.
    let slow = format!("{}.eth", "a".repeat(600_000));
    let mut batch = common::frame(&request(
        500,
        "naming.resolve_content",
        json!({ "name": slow, "private": false }),
    ));
    batch.extend(common::frame(&json!({
        "type": "response",
        "id": first,
        "error": { "code": "network", "message": "Network error" },
    })));
    batch.extend(common::frame(&request(501, "core.shutdown", json!({}))));
    core.send_raw(&batch);
    core.close_stdin();
    let rest = core.rest();
    let acknowledged = rest
        .iter()
        .position(|m| m["id"] == 501 && m["type"] == "response")
        .expect("the shutdown reply");
    assert!(
        !rest[acknowledged..].iter().any(|m| m["type"] == "request"),
        "a request after the shutdown reply"
    );
}

#[test]
fn configure_reports_every_generation() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let configured = core.call(2, "naming.configure", snapshot());
    assert_eq!(
        configured["result"],
        json!({ "ens": 1, "tezos": 1, "lifecycle": 0 })
    );
    // A provider reset advances the lifecycle, which main tracks.
    let mut reset = snapshot();
    reset["reset"] = json!("providers");
    let reset = core.call(3, "naming.configure", reset);
    assert_eq!(
        reset["result"],
        json!({ "ens": 1, "tezos": 1, "lifecycle": 1 })
    );
}

/// Design 0003, decision 4: the core owns the result cache, so every
/// cached subresource lookup is a round trip to it. This measures a page's
/// worth of cache hits, alone and while the vault runs its password KDF.
/// Run it on a release build:
///   cargo test --release -p freedom-cored --test naming -- --ignored --nocapture fanout
#[test]
#[ignore = "a measurement, not a check"]
// It reports what it measured.
#[allow(clippy::print_stdout)]
fn cached_fanout_under_vault_work() {
    const BURST: u64 = 50;
    const ROUNDS: u64 = 20;
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(2, "naming.configure", snapshot());
    let password = base64::engine::general_purpose::STANDARD.encode("fanout-password");
    let created = core.call(
        3,
        "vault.create",
        json!({ "password_b64": password, "words": 12 }),
    );
    assert!(created["result"].is_object(), "{created}");
    // One lookup through main fills the cache.
    core.send(&request(
        4,
        "naming.resolve_content",
        json!({ "name": "vitalik.eth", "private": false }),
    ));
    let (reply, _) = serve_until(&mut core, 4, &recorded());
    assert_eq!(reply["result"]["result"]["type"], "ok", "{reply}");

    let mut next = 100;
    // A burst of cache hits, with `kdfs` password checks sent just before:
    // each hit's time from send to reply.
    let mut burst = |core: &mut common::Core, kdfs: u64| -> (Vec<Duration>, Duration) {
        let mut sent = BTreeMap::new();
        let mut checks = Vec::new();
        for _ in 0..kdfs {
            next += 1;
            core.send(&request(
                next,
                "vault.verify_password",
                json!({ "password_b64": password }),
            ));
            checks.push((next, Instant::now()));
        }
        for _ in 0..BURST {
            next += 1;
            core.send(&request(
                next,
                "naming.resolve_content",
                json!({ "name": "vitalik.eth", "private": false }),
            ));
            sent.insert(next, Instant::now());
        }
        let mut hits = Vec::new();
        let mut kdf = Duration::ZERO;
        while !sent.is_empty() || !checks.is_empty() {
            let message = core.recv();
            if message["type"] != "response" {
                continue;
            }
            let id = message["id"].as_u64().unwrap();
            if let Some(at) = sent.remove(&id) {
                assert_eq!(message["result"]["attempts"], 0, "a cache hit: {message}");
                hits.push(at.elapsed());
            } else if let Some(i) = checks.iter().position(|(c, _)| *c == id) {
                assert_eq!(message["result"], json!({}), "{message}");
                kdf = kdf.max(checks.remove(i).1.elapsed());
            }
        }
        (hits, kdf)
    };
    let quantile = |all: &mut Vec<Duration>, q: f64| {
        all.sort();
        let at = ((all.len() as f64 - 1.0) * q).round() as usize;
        all[at]
    };
    for kdfs in [0, 1, 4, 16] {
        let mut all = Vec::new();
        let mut slowest_kdf = Duration::ZERO;
        for _ in 0..ROUNDS {
            let (hits, kdf) = burst(&mut core, kdfs);
            all.extend(hits);
            slowest_kdf = slowest_kdf.max(kdf);
        }
        println!(
            "{BURST} cache hits x {ROUNDS} with {kdfs:>2} KDFs in flight: \
             p50 {:?}, p99 {:?}, max {:?}; slowest KDF {:?}",
            quantile(&mut all, 0.5),
            quantile(&mut all, 0.99),
            quantile(&mut all, 1.0),
            slowest_kdf,
        );
    }
}
