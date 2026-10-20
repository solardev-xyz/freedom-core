//! The budgets and `ipfs.stats` through the binary (design 0007, "Budgets"
//! and "Stats"). Instances route offline; a fetch that leaves the store goes
//! to the HTTP provider its store records, on loopback, which never answers.
//! The budgets are small and the waits short by test hooks.

#![cfg(feature = "testhooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

const MIB: usize = 1 << 20;
/// The writer's queue, reserved at process start.
const WRITER: usize = 16 * MIB;
/// A private instance's fixed reservation: 36 + 4 + 2 + 1.
const PRIVATE: usize = 43 * MIB;
/// The persistent instance's: 8 + 16 + 2 + 1.
const PERSISTENT: usize = 27 * MIB;
const RAW: u64 = 0x55;
const DAG_PB: u64 = 0x70;

fn budget(bytes: usize) -> String {
    bytes.to_string()
}

fn stats(ipfsd: &mut Ipfsd, instance: &str) -> Value {
    let reply = ipfsd.call("ipfs.stats", json!({ "instance": instance }));
    assert!(reply["result"].is_object(), "{reply}");
    reply["result"].clone()
}

/// The instance's gateway counters once `freed` requests have ended (or
/// after 10 s): a request's outcome is counted as its work ends, a moment
/// after its terminal is queued, and before its admission ends.
fn gateway_after(ipfsd: &mut Ipfsd, freed: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let gateway = stats(ipfsd, "p-1")["gateway"].clone();
        if gateway["total_freed"] == freed || Instant::now() > deadline {
            return gateway;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn shut_down(mut ipfsd: Ipfsd) -> String {
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    ipfsd.stderr()
}

#[test]
fn a_start_is_admitted_only_within_the_free_budget_and_its_reservation_returns_after_teardown() {
    // The writer, one private instance and a little more.
    let limit = budget(WRITER + PRIVATE + MIB);
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_MEMORY_BUDGET", &limit)]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    let memory_use = &stats(&mut ipfsd, "e-1")["budget"]["memory"];
    assert_eq!(memory_use["used"], WRITER + PRIVATE, "{memory_use}");
    assert_eq!(memory_use["limit"], WRITER + PRIVATE + MIB);
    // A second doesn't fit: `busy`, and it takes nothing, its ID included.
    let refused = ipfsd.start(memory("e-2"));
    assert_eq!(refused["error"]["code"], "busy", "{refused}");
    assert_eq!(
        stats(&mut ipfsd, "e-1")["budget"]["memory"]["used"],
        WRITER + PRIVATE
    );
    // Once the first's teardown is proven, its reservation is free again.
    assert_eq!(ipfsd.stop("e-1")["result"]["instance"], "e-1");
    assert_eq!(ipfsd.start(memory("e-2"))["result"]["instance"], "e-2");
    assert_eq!(
        stats(&mut ipfsd, "e-2")["budget"]["memory"]["used"],
        WRITER + PRIVATE
    );
    shut_down(ipfsd);

    // The persistent instance alike.
    let dirs = Dirs::new();
    let limit = budget(WRITER + PERSISTENT - 1);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[("FREEDOM_IPFSD_TEST_MEMORY_BUDGET", &limit)]);
    ipfsd.hello();
    let refused = ipfsd.start(disk("p-1"));
    assert_eq!(refused["error"]["code"], "busy", "{refused}");
    shut_down(ipfsd);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    let memory_use = &stats(&mut ipfsd, "p-1")["budget"]["memory"];
    assert_eq!(
        (&memory_use["used"], &memory_use["limit"]),
        (&json!(WRITER + PERSISTENT), &json!(192 * MIB)),
        "{memory_use}"
    );
    assert_eq!(ipfsd.stop("p-1")["result"]["instance"], "p-1");
    assert_eq!(ipfsd.start(disk("p-2"))["result"]["instance"], "p-2");
    assert_eq!(
        stats(&mut ipfsd, "p-2")["budget"]["memory"]["used"],
        WRITER + PERSISTENT,
        "p-1's reservations all came back"
    );
    shut_down(ipfsd);
}

/// A persistent process whose budget holds the writer, the instance's fixed
/// reservation and 1 MiB: no fetch's 2 MiB fits. Its instance's routing is
/// offline, so it asks only the providers the store records.
fn starved(dirs: &Dirs, env: &[(&str, &str)]) -> Ipfsd {
    let limit = budget(WRITER + PERSISTENT + MIB);
    let mut env = env.to_vec();
    env.push(("FREEDOM_IPFSD_TEST_MEMORY_BUDGET", &limit));
    let mut ipfsd = Ipfsd::persistent(dirs, &env);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    ipfsd
}

#[test]
fn a_request_that_cannot_reserve_before_its_head_waits_then_is_busy() {
    let provider = Server::start();
    let dirs = Dirs::new();
    let missing = freedom_ipfs_core::cid_from_data(RAW, b"not stored anywhere").to_string();
    seed_provider(&dirs, std::slice::from_ref(&missing), &provider);
    let mut ipfsd = starved(&dirs, &[]);
    let sent = Instant::now();
    let id = ipfsd.request(
        "ipfs.request",
        json!({ "instance": "p-1", "method": "GET", "path": format!("/ipfs/{missing}"),
            "headers": [], "headers_ms": 1000 }),
    );
    let reply = ipfsd.reply(id);
    let waited = sent.elapsed();
    assert_eq!(reply["error"]["code"], "busy", "{reply}");
    // It waited for memory until just before its headers_ms, and asked the
    // provider nothing.
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert_eq!(provider.accepted(), 0);
    let gateway = &gateway_after(&mut ipfsd, 1);
    assert_eq!(
        (&gateway["total_failed"], &gateway["last_native_error_code"]),
        (&json!(1), &json!("busy")),
        "{gateway}"
    );
    shut_down(ipfsd);
}

#[test]
fn a_streams_next_fetch_that_cannot_reserve_waits_then_aborts_busy() {
    let provider = Server::start();
    let dirs = Dirs::new();
    // A file of two 64 KiB leaves: the first stored, the second not.
    let first = vec![1u8; 64 << 10];
    let second = freedom_ipfs_core::cid_from_data(RAW, &[2u8; 64 << 10]);
    seed_provider(&dirs, &[second.to_string()], &provider);
    let leaves = seed_blocks(&dirs, &[(RAW, first.clone())]);
    let file = pb_file(&[
        (leaves[0].0.clone(), 64 << 10),
        (second.to_bytes(), 64 << 10),
    ]);
    let root = seed_blocks(&dirs, &[(DAG_PB, file)]);
    let mut ipfsd = starved(
        &dirs,
        &[("FREEDOM_IPFSD_TEST_STREAM_MEMORY_WAIT_MS", "400")],
    );
    let id = ipfsd.request("ipfs.request", get("p-1", &format!("/ipfs/{}", root[0].1)));
    let head = ipfsd.reply(id);
    assert_eq!(
        (&head["result"]["status"], &head["result"]["body"]),
        (&json!(200), &json!(true)),
        "{head}"
    );
    let started = Instant::now();
    let (body, terminal) = ipfsd.body(id);
    let waited = started.elapsed();
    assert_eq!(body, first, "the stored leaf is served");
    assert_eq!(
        (&terminal["stream"], &terminal["code"]),
        (&json!("abort"), &json!("busy")),
        "{terminal}"
    );
    // Its next fetch waited for memory as long as the override says, not
    // 10 s, and asked the provider nothing.
    assert!(
        (Duration::from_millis(350)..Duration::from_secs(5)).contains(&waited),
        "{waited:?}"
    );
    assert_eq!(provider.accepted(), 0);
    let gateway = &gateway_after(&mut ipfsd, 1);
    assert_eq!(
        (
            &gateway["total_failed"],
            &gateway["last_native_error_code"],
            &gateway["bytes_read"]
        ),
        (&json!(1), &json!("busy"), &json!(64 << 10)),
        "{gateway}"
    );
    shut_down(ipfsd);
}

/// A page whose 200 scripts are missing, their provider recorded: with HTML
/// prefetch on (for tests only), each script's prefetch is background work,
/// and each waits for a provider that never answers. The process serves the
/// page, its memory budget `budget` if given.
fn prefetching(budget: Option<String>) -> (Ipfsd, Server) {
    let provider = Server::start();
    let dirs = Dirs::new();
    let assets: Vec<_> = (0..200)
        .map(|n| {
            let name = format!("a{n}.js");
            let cid = freedom_ipfs_core::cid_from_data(RAW, name.as_bytes());
            (name, cid)
        })
        .collect();
    let cids: Vec<String> = assets.iter().map(|(_, cid)| cid.to_string()).collect();
    seed_provider(&dirs, &cids, &provider);
    let html: String = std::iter::once("<!doctype html><html><head>".to_owned())
        .chain(
            assets
                .iter()
                .map(|(name, _)| format!("<script src=\"{name}\"></script>")),
        )
        .chain(std::iter::once("</head></html>".to_owned()))
        .collect();
    let page = seed_blocks(&dirs, &[(RAW, html.clone().into_bytes())]);
    let mut entries: Vec<(&str, Vec<u8>, u64)> =
        vec![("index.html", page[0].0.clone(), html.len() as u64)];
    entries.extend(
        assets
            .iter()
            .map(|(name, cid)| (name.as_str(), cid.to_bytes(), 10)),
    );
    let directory = seed_blocks(&dirs, &[(DAG_PB, pb_directory(&entries))]);
    let mut env = vec![("FREEDOM_IPFSD_TEST_HTML_PREFETCH_ASSETS", "200")];
    if let Some(budget) = &budget {
        env.push(("FREEDOM_IPFSD_TEST_MEMORY_BUDGET", budget));
    }
    let mut ipfsd = Ipfsd::persistent(&dirs, &env);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    let id = ipfsd.request(
        "ipfs.request",
        get("p-1", &format!("/ipfs/{}/index.html", directory[0].1)),
    );
    assert_eq!(ipfsd.reply(id)["result"]["status"], 200);
    assert_eq!(ipfsd.body(id).0, html.as_bytes());
    (ipfsd, provider)
}

/// The instance's background queue, once `done` says so, or after 10 s.
fn background_until(ipfsd: &mut Ipfsd, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let background = stats(ipfsd, "p-1")["budget"]["background"].clone();
        if done(&background) || Instant::now() > deadline {
            return background;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn background_work_past_its_queue_is_dropped() {
    let (mut ipfsd, _provider) = prefetching(None);
    let background = background_until(&mut ipfsd, |background| background["dropped"] != 0);
    assert_eq!(background["limit"], 64, "{background}");
    assert!(
        background["outstanding"].as_u64().unwrap() <= 64,
        "{background}"
    );
    assert!(
        background["dropped"].as_u64().unwrap() >= 200 - 64,
        "past the queue's 64, dropped: {background}"
    );
    shut_down(ipfsd);
}

#[test]
fn background_work_never_waits_for_memory() {
    // No fetch's 2 MiB fits: each prefetch fails at once rather than wait,
    // so the queue drains, and the provider is asked nothing.
    let (mut ipfsd, provider) = prefetching(Some(budget(WRITER + PERSISTENT + MIB)));
    let background = background_until(&mut ipfsd, |background| background["outstanding"] == 0);
    // Some were admitted, and every one of them has ended.
    assert!(
        background["dropped"].as_u64().unwrap() < 200,
        "{background}"
    );
    assert_eq!(background["outstanding"], 0, "{background}");
    assert_eq!(provider.accepted(), 0);
    shut_down(ipfsd);
}

#[test]
fn stats_count_what_the_requests_did() {
    let dirs = Dirs::new();
    let one = vec![3u8; 1000];
    let two = vec![4u8; 100 << 10];
    let cids = seed(&dirs, &[one.clone(), two.clone()]);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[("FREEDOM_IPFSD_TEST_REQUEST_HOOKS", "1")]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    let fresh = stats(&mut ipfsd, "p-1");
    assert_eq!(
        fresh["gateway"],
        json!({ "active_native_handles": 0, "total_started": 0, "total_completed": 0,
            "total_failed": 0, "total_cancelled": 0, "total_freed": 0,
            "total_gateway_busy_responses": 0, "bytes_read": 0, "max_active_handles": 0,
            "last_native_error_code": null, "last_native_error_message": null })
    );
    assert_eq!(fresh["progress"], Value::Null);
    assert_eq!(
        fresh["store"],
        json!({ "block_count": 2, "total_bytes": one.len() + two.len() })
    );
    for (name, limit) in [
        ("block_fetches", 256),
        ("http_provider_requests", 16),
        ("bitswap_connections", 32),
        ("dht_queries", 4),
        ("requests", 512),
        ("writer", WRITER),
        ("background", 64),
    ] {
        assert_eq!(fresh["budget"][name]["limit"], limit, "{name}");
    }

    let mut read = 0;
    // Two bodies, and a HEAD.
    for cid in &cids {
        let id = ipfsd.request("ipfs.request", get("p-1", &format!("/ipfs/{cid}")));
        assert_eq!(ipfsd.reply(id)["result"]["status"], 200);
        read += ipfsd.body(id).0.len();
    }
    let id = ipfsd.request(
        "ipfs.request",
        json!({ "instance": "p-1", "method": "HEAD", "path": format!("/ipfs/{}", cids[0]),
            "headers": [], "headers_ms": 30000 }),
    );
    assert_eq!(ipfsd.reply(id)["result"]["body"], false);
    // A cancel before its head, and a deadline.
    let held = |headers_ms: u64| {
        json!({ "instance": "p-1", "method": "GET", "path": format!("/ipfs/{}", cids[0]),
            "headers": [["x-freedom-test-hold", "head"]], "headers_ms": headers_ms })
    };
    let cancelled = ipfsd.request("ipfs.request", held(30_000));
    let late = ipfsd.request("ipfs.request", held(200));
    assert_eq!(ipfsd.reply(late)["error"]["code"], "deadline");
    ipfsd.cancel(cancelled);
    assert_eq!(ipfsd.reply(cancelled)["error"]["code"], "cancelled");
    let gateway = gateway_after(&mut ipfsd, 5);
    assert_eq!(
        gateway,
        json!({ "active_native_handles": 0, "total_started": 5, "total_completed": 3,
            "total_failed": 1, "total_cancelled": 1, "total_freed": 5,
            "total_gateway_busy_responses": 0, "bytes_read": read,
            "max_active_handles": gateway["max_active_handles"],
            "last_native_error_code": "deadline",
            "last_native_error_message": "no head within headers_ms" })
    );
    assert!(
        gateway["max_active_handles"].as_u64().unwrap() >= 2,
        "{gateway}"
    );
    assert_eq!(read, one.len() + two.len());
    // And what they held is back: their heads' charges, their admissions,
    // the writer's queue.
    let budget = &stats(&mut ipfsd, "p-1")["budget"];
    assert_eq!(
        (
            &budget["memory"]["used"],
            &budget["requests"]["admitted"],
            &budget["writer"]["queued"]
        ),
        (&json!(WRITER + PERSISTENT), &json!(0), &json!(0)),
        "{budget}"
    );

    // Not live, or malformed.
    assert_eq!(
        ipfsd.call("ipfs.stats", json!({ "instance": "p-9" }))["error"]["code"],
        "stopped"
    );
    assert_eq!(
        ipfsd.call("ipfs.stats", json!({ "instance": "p-1", "x": 1 }))["error"]["code"],
        "invalid_argument"
    );
    shut_down(ipfsd);
}

#[test]
fn stats_count_the_gateways_busy_heads() {
    let provider = Server::start();
    let dirs = Dirs::new();
    let missing = freedom_ipfs_core::cid_from_data(RAW, b"held at its provider").to_string();
    seed_provider(&dirs, std::slice::from_ref(&missing), &provider);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    ipfsd.hello();
    // One request at a time in the gateway, and 100 ms in its queue.
    let mut params = disk("p-1");
    params["gateway"] = json!({ "max_concurrent_requests": 1, "request_queue_timeout_ms": 100 });
    assert_eq!(ipfsd.start(params)["result"]["instance"], "p-1");
    let path = format!("/ipfs/{missing}");
    let holding = ipfsd.request("ipfs.request", get("p-1", &path));
    let deadline = Instant::now() + Duration::from_secs(10);
    while provider.accepted() == 0 {
        assert!(Instant::now() < deadline, "the first request never fetched");
        std::thread::sleep(Duration::from_millis(10));
    }
    let refused = ipfsd.request("ipfs.request", get("p-1", &path));
    let head = ipfsd.reply(refused);
    assert_eq!(head["result"]["status"], 503, "{head}");
    ipfsd.body(refused);
    ipfsd.cancel(holding);
    assert_eq!(ipfsd.reply(holding)["error"]["code"], "cancelled");
    let gateway = gateway_after(&mut ipfsd, 2);
    assert_eq!(
        (
            &gateway["total_gateway_busy_responses"],
            &gateway["last_native_error_code"],
            &gateway["last_native_error_message"],
        ),
        (&json!(1), &json!("gateway_busy"), &json!("gateway busy")),
        "{gateway}"
    );
    assert_eq!(
        (
            &gateway["total_started"],
            &gateway["total_completed"],
            &gateway["total_failed"],
            &gateway["total_cancelled"],
            &gateway["active_native_handles"],
        ),
        (&json!(2), &json!(1), &json!(0), &json!(1), &json!(0)),
        "{gateway}"
    );
    shut_down(ipfsd);
}

#[test]
fn a_pending_head_holds_its_size_until_the_writer_takes_it() {
    let dirs = Dirs::new();
    // One credit window of body: more than a pipe's buffer.
    let body = vec![5u8; 128 << 10];
    let cids = seed(&dirs, &[body.clone(), b"small".to_vec()]);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    // Main stops reading: the writer blocks inside the first body, so the
    // second's head waits in its queue, and its size is held meanwhile.
    ipfsd.pause_reading();
    let first = ipfsd.request("ipfs.request", get("p-1", &format!("/ipfs/{}", cids[0])));
    std::thread::sleep(Duration::from_millis(500));
    let second = ipfsd.request("ipfs.request", get("p-1", &format!("/ipfs/{}", cids[1])));
    // Asked a few times over a second and a half, so the last one sees the
    // second's head queued, however slowly its work runs.
    let during: Vec<u64> = (0..6)
        .map(|_| {
            std::thread::sleep(Duration::from_millis(250));
            ipfsd.request("ipfs.stats", json!({ "instance": "p-1" }))
        })
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    ipfsd.resume_reading();
    let used: Vec<usize> = during
        .iter()
        .map(|id| {
            ipfsd.reply(*id)["result"]["budget"]["memory"]["used"]
                .as_u64()
                .unwrap() as usize
        })
        .collect();
    let held = used[used.len() - 1];
    assert!(
        (WRITER + PERSISTENT + 64..WRITER + PERSISTENT + 4096).contains(&held),
        "a head's size, held: {}",
        held - (WRITER + PERSISTENT)
    );
    assert_eq!(ipfsd.body(first).0, body);
    assert_eq!(ipfsd.reply(second)["result"]["status"], 200);
    assert_eq!(ipfsd.body(second).0, b"small");
    // Written: released.
    assert_eq!(
        stats(&mut ipfsd, "p-1")["budget"]["memory"]["used"],
        WRITER + PERSISTENT
    );
    shut_down(ipfsd);
}
