//! `rad.stats` through the real binary (design 0008, "Methods", "The unit
//! watchdog", "Main's side" and "Tests first": "Units and the watchdog":
//! "`rad.stats` stays answered, and shows the unit's elapsed time"). It is
//! answered inline, in every phase from the handshake on, never waiting;
//! its values that change with time (elapsed times, counts, bytes) are
//! checked for their shape and bounds here, and the result's bytes for
//! each state against `vectors/radicle-stats.json` in the unit tests
//! (src/stats/tests.rs).
//!
//! Every node here reaches no one, as in tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::fixture;
use common::*;
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::quarantine::Kind;
use serde_json::{Value, json};

const MIB: u64 = 1 << 20;
/// The output budget (0008, "Pools and budgets").
const BUDGET: u64 = 256 * MIB;
/// The result's most bytes: one frame, and far less than one.
const MAX_RESULT: usize = 4096;
const LOOK_HOLDS: &str = "test hook: the watch's look holds the node";

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or_default()
}

/// `rad.stats`'s result, with its shape checked: every member, of its
/// type, its bounds held, and the pools' shapes and the budget's limit
/// 0008's.
fn stats(radicled: &mut Radicled) -> Value {
    let reply = radicled.call("rad.stats", json!({}));
    let result = reply["result"].clone();
    assert!(result.is_object(), "{reply}");
    let keys: Vec<&str> = result
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "node",
            "node_alive",
            "connected_peers",
            "unit",
            "quarantined_count",
            "pools",
            "budget",
            "network"
        ],
        "{result}"
    );
    assert!(serde_json::to_string(&result).unwrap().len() <= MAX_RESULT);
    let node = result["node"].as_str().unwrap();
    assert!(
        ["waiting", "starting", "running", "down", "stopped"].contains(&node),
        "{result}"
    );
    let alive = result["node_alive"].as_bool().unwrap();
    assert!(!alive || node == "running", "{result}");
    assert!(
        result["connected_peers"].is_null() || result["connected_peers"].is_u64(),
        "{result}"
    );
    if node != "running" {
        assert!(result["connected_peers"].is_null(), "{result}");
    }
    if let Some(unit) = result["unit"].as_object() {
        assert!(unit["kind"].is_string(), "{result}");
        assert!(unit["elapsed_ms"].is_u64(), "{result}");
        assert!(unit["limit_ms"].is_u64(), "{result}");
    } else {
        assert!(result["unit"].is_null(), "{result}");
    }
    assert!(
        result["quarantined_count"].is_null() || result["quarantined_count"].is_u64(),
        "{result}"
    );
    for (name, threads, queue) in [("read", 4, 320), ("network", 8, 16), ("write", 1, 16)] {
        let pool = &result["pools"][name];
        assert_eq!(pool["threads"], threads, "{result}");
        assert_eq!(pool["queue"], queue, "{result}");
        assert!(pool["running"].as_u64().unwrap() <= threads, "{result}");
        assert!(pool["queued"].as_u64().unwrap() <= queue, "{result}");
        assert_eq!(pool.get("repairs").is_some(), name == "write", "{result}");
    }
    let output = &result["budget"]["output"];
    assert!(
        output["used"].as_u64().unwrap() <= output["limit"].as_u64().unwrap(),
        "{result}"
    );
    let nat64 = &result["network"]["nat64"];
    if !nat64.is_null() {
        assert_eq!(result["network"]["mode"], "direct", "{result}");
        assert_eq!(node, "running", "{result}");
        assert!(
            nat64["prefixes"].as_array().unwrap().len() <= 16,
            "{result}"
        );
        assert!(
            nat64["failures"].as_array().unwrap().len() <= 16,
            "{result}"
        );
    }
    result
}

/// `rad.stats` asked until `done` holds of its result, within 20 s.
fn stats_until(radicled: &mut Radicled, done: impl Fn(&Value) -> bool) -> Value {
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        let result = stats(radicled);
        if done(&result) {
            return result;
        }
        assert!(Instant::now() < until, "never: {result}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn idle_pools() -> Value {
    json!({
        "read": { "running": 0, "queued": 0, "threads": 4, "queue": 320 },
        "network": { "running": 0, "queued": 0, "threads": 8, "queue": 16 },
        "write": { "running": 0, "queued": 0, "threads": 1, "queue": 16, "repairs": 0 },
    })
}

/// 0008, "Methods" and "Main's side": from the handshake to a clean stop,
/// `rad.stats` is answered at once, the node's phase and liveness, its
/// peers once counted, the quarantine's count once reconciled, the idle
/// pools, the budget, and NAT64 once the node runs in `direct` mode. Its
/// params are checked, and a refusal ends nothing. Asking it never spoils
/// a clean stop.
#[test]
fn stats_follow_the_service_from_the_handshake_to_a_clean_stop() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    let first = stats(&mut radicled);
    assert_eq!(
        first,
        json!({
            "node": "waiting",
            "node_alive": false,
            "connected_peers": null,
            "unit": null,
            "quarantined_count": null,
            "pools": idle_pools(),
            "budget": { "output": { "used": 0, "limit": BUDGET } },
            "network": { "mode": "direct", "nat64": null },
        })
    );
    // Params: none, null or `{}`; anything else is refused, and the
    // process goes on.
    for params in [json!(null), json!({})] {
        let reply = radicled.call("rad.stats", params);
        assert_eq!(reply["result"], first, "{reply}");
    }
    for params in [json!({ "page": 0 }), json!([]), json!(1)] {
        let reply = radicled.call("rad.stats", params.clone());
        assert_eq!(code(&reply), "invalid_argument", "{params}: {reply}");
        assert_eq!(
            reply["error"]["message"], "rad.stats takes no params",
            "{reply}"
        );
    }

    let identity = radicled.call("rad.identity", sealed_to(&hello, &SEED));
    assert!(identity["result"].is_object(), "{identity}");
    assert_eq!(stats(&mut radicled)["quarantined_count"], Value::Null);
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert!(reconciled["result"].is_object(), "{reconciled}");
    let result = stats(&mut radicled);
    assert_eq!(result["node"], "waiting", "{result}");
    assert_eq!(result["quarantined_count"], 0, "{result}");
    assert!(radicled.call("rad.start", json!({ "alias": "stats" }))["result"].is_object());

    let result = stats(&mut radicled);
    assert_eq!(result["node"], "running", "{result}");
    assert_eq!(result["node_alive"], true, "{result}");
    assert_eq!(result["pools"], idle_pools(), "{result}");
    // The watch counts the peers within a second or so; no resolver to ask,
    // so discovery settles known, with no prefix.
    let result = stats_until(&mut radicled, |r| {
        r["connected_peers"].is_u64() && r["network"]["nat64"]["state"] == "known"
    });
    assert_eq!(result["connected_peers"], 0, "{result}");
    assert_eq!(
        result["network"],
        json!({ "mode": "direct", "nat64": { "state": "known", "prefixes": [], "failures": [] } })
    );
    assert_eq!(result["quarantined_count"], 0, "{result}");
    assert_eq!(result["unit"], Value::Null, "{result}");
    // Many in a row, as fast as main could ask: each at once.
    let asked = Instant::now();
    for _ in 0..200 {
        assert_eq!(stats(&mut radicled)["node_alive"], true);
    }
    assert!(asked.elapsed() < Duration::from_secs(20));

    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);
}

/// A dirty home, where reconciliation runs every kind of unit
/// (tests/units.rs).
fn dirty_home(dirs: &Dirs, name: &str) -> RepoId {
    let rid = fixture::repository(&dirs.home, &SEED, name);
    fixture::unsigned_ref(&dirs.home, rid, NID);
    fixture::mark(&dirs.home, &[NID]);
    rid
}

/// The unit in progress, as `rad.stats` reports it, its kind `kind`.
/// The hung unit's limit in the tests of a hung unit
/// (`FREEDOM_RADICLED_TEST_HANG_LIMIT_MS`): room for the test to read
/// `rad.stats` twice, 600 ms apart, before it fires, however slowly a
/// runner answers. Only the hung unit's kind gets it: every unit before it
/// keeps its 30 s, so one that a slow runner's disk holds up never fires in
/// its place.
const HANG_LIMIT_MS: u64 = 8000;

fn unit_of(radicled: &mut Radicled, kind: &str) -> Value {
    let result = stats_until(radicled, |r| r["unit"]["kind"] == kind);
    result["unit"].clone()
}

/// 0008, "The unit watchdog" ("`rad.stats` reports the unit in progress and
/// its elapsed time"): a unit of reconciliation that hangs, before any node
/// runs: `rad.stats` stays answered, the unit's kind, its time growing and
/// its limit, until the watchdog ends the process.
#[test]
fn a_hung_unit_of_reconciliation_is_reported_until_the_watchdog_fires() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    dirty_home(&dirs, "hung");
    let limit = HANG_LIMIT_MS.to_string();
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HANG_UNIT", "cache"),
            ("FREEDOM_RADICLED_TEST_HANG_LIMIT_MS", &limit),
        ],
    );
    let hello = radicled.hello();
    let identity = radicled.call("rad.identity", sealed_to(&hello, &SEED));
    assert!(identity["result"].is_object(), "{identity}");
    radicled.request("rad.reconcile", json!({}));
    let first = unit_of(&mut radicled, "cache");
    assert_eq!(first["limit_ms"], HANG_LIMIT_MS, "{first}");
    std::thread::sleep(Duration::from_millis(600));
    let later = unit_of(&mut radicled, "cache");
    let (first_ms, later_ms) = (
        first["elapsed_ms"].as_u64().unwrap(),
        later["elapsed_ms"].as_u64().unwrap(),
    );
    assert!(later_ms >= first_ms + 500, "{first} {later}");
    assert!(later_ms <= HANG_LIMIT_MS + 1000, "{later}");
    let result = stats(&mut radicled);
    assert_eq!(result["node"], "waiting", "{result}");
    assert_eq!(result["quarantined_count"], Value::Null, "{result}");
    assert_eq!(radicled.exit_code(OVERRUN_EXIT_TIMEOUT), Some(70));
    // The bound that ran out is the one `rad.stats` reported.
    let log = radicled.stderr();
    assert_eq!(overrun(&log)["bound_ms"], HANG_LIMIT_MS, "{log}");
}

/// 0008, "Tests first" ("a COB that never returns during an online
/// repair: `rad.stats` stays answered, and shows the unit's elapsed
/// time"): the online repair's unit on the writer, the node alive beside
/// it, until the watchdog ends the process (tests/repair.rs's hang).
#[test]
fn a_hung_unit_of_an_online_repair_is_reported_while_the_node_runs() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &SEED, "hanging");
    fixture::unsigned_ref(&dirs.home, rid, NID);
    // No marker: the first cache unit is the online repair's.
    let limit = HANG_LIMIT_MS.to_string();
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HANG_UNIT", "cache"),
            ("FREEDOM_RADICLED_TEST_HANG_LIMIT_MS", &limit),
        ],
    );
    assert!(radicled.start()["result"].is_object());
    let uncertain = json!({
        "op": "comment_issue",
        "args": { "rid": rid.to_string(), "issue_id": "abcdef0123", "body": "Nowhere." },
    });
    let reply = radicled.call("rad.write", uncertain);
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    let first = unit_of(&mut radicled, "cache");
    assert_eq!(first["limit_ms"], HANG_LIMIT_MS, "{first}");
    let result = stats(&mut radicled);
    assert_eq!(result["node"], "running", "{result}");
    assert_eq!(result["node_alive"], true, "{result}");
    // The repair is the writer's, not a request's: queued until it is over.
    assert_eq!(result["pools"]["write"]["repairs"], 1, "{result}");
    assert_eq!(result["pools"]["write"]["running"], 0, "{result}");
    std::thread::sleep(Duration::from_millis(600));
    let later = unit_of(&mut radicled, "cache");
    assert!(
        later["elapsed_ms"].as_u64().unwrap() >= first["elapsed_ms"].as_u64().unwrap() + 500,
        "{first} {later}"
    );
    assert_eq!(radicled.exit_code(OVERRUN_EXIT_TIMEOUT), Some(70));
    let log = radicled.stderr();
    assert_eq!(overrun(&log)["bound_ms"], HANG_LIMIT_MS, "{log}");
}

/// 0008, "Pools and budgets": each pool's requests running and queued, as
/// work holds its slots, and back to idle as they end; the output budget's
/// bytes held by bodies main doesn't credit, at most its limit, as the
/// reference's contract suite reads them, and freed as they are cancelled.
#[test]
fn the_pools_and_the_budget_in_use() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, commits) = fixture::repository_with(
        &dirs.home,
        &SEED,
        "budget",
        &[&[("half.txt", &vec![b'a'; 1 << 20])]],
    );
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_WORK", "1")]);
    assert!(radicled.start()["result"].is_object());
    // Five reads: four running, one queued. A clone and a write, each held.
    let mut held: Vec<u64> = (0..5)
        .map(|_| radicled.request("rad.read", json!({ "op": "status" })))
        .collect();
    held.push(radicled.request(
        "rad.clone",
        json!({ "rid": rid.to_string(), "timeout_ms": 30000 }),
    ));
    held.push(radicled.request("rad.unseed", json!({ "rid": rid.to_string() })));
    held.push(radicled.request("rad.unseed", json!({ "rid": rid.to_string() })));
    let result = stats_until(&mut radicled, |r| {
        r["pools"]["read"]["running"] == 4
            && r["pools"]["network"]["running"] == 1
            && r["pools"]["write"]["running"] == 1
    });
    assert_eq!(
        result["pools"],
        json!({
            "read": { "running": 4, "queued": 1, "threads": 4, "queue": 320 },
            "network": { "running": 1, "queued": 0, "threads": 8, "queue": 16 },
            "write": { "running": 1, "queued": 1, "threads": 1, "queue": 16, "repairs": 0 },
        })
    );
    for id in &held {
        radicled.cancel(*id);
    }
    for id in &held {
        assert_eq!(code(&radicled.reply(*id)), "cancelled");
    }
    stats_until(&mut radicled, |r| r["pools"] == idle_pools());
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));

    // Four bodies main doesn't credit past their window: each holds the
    // rest of its JSON.
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    let args = json!({ "rid": rid.to_string(), "revision": commits[0], "path": "half.txt" });
    let bodies: Vec<u64> = (0..4)
        .map(|_| radicled.request("rad.read", json!({ "op": "blob_at", "args": args })))
        .collect();
    for id in &bodies {
        assert!(radicled.reply(*id)["result"].is_object());
        radicled.uncredited(*id, 128 << 10);
    }
    let result = stats(&mut radicled);
    let output = &result["budget"]["output"];
    assert_eq!(output["limit"], BUDGET, "{result}");
    let used = output["used"].as_u64().unwrap();
    assert!(used >= 4 * (MIB - (128 << 10)), "{result}");
    assert!(used <= BUDGET, "{result}");
    assert_eq!(result["pools"]["read"]["running"], 4, "{result}");
    for id in &bodies {
        radicled.cancel(*id);
        assert_eq!(radicled.stream(*id)["stream"], "abort");
    }
    stats_until(&mut radicled, |r| r["budget"]["output"]["used"] == 0);
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));

    // The budget a test hook shrinks: its own limit.
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_BUDGET", "68157440")]);
    radicled.hello();
    assert_eq!(
        stats(&mut radicled)["budget"]["output"]["limit"],
        68157440u64
    );
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// 0008, "The escape": the record's count, from reconciliation's report,
/// then again as `rad.remove_repo` removes a repository and as an online
/// repair quarantines one.
#[test]
fn the_quarantined_count_follows_the_record() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let quarantined: Vec<RepoId> = ["one", "two", "three"]
        .iter()
        .map(|name| fixture::repository(&dirs.home, &fixture::OTHER_SEED, name))
        .collect();
    for rid in &quarantined {
        fixture::quarantine(&dirs.home, *rid, Kind::Namespace);
    }
    let broken = fixture::repository(&dirs.home, &SEED, "broken");
    fixture::missing_object_ref(&dirs.home, broken, NID);
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    assert_eq!(stats(&mut radicled)["quarantined_count"], 3);

    let listed = radicled.call("rad.quarantine_list", json!({ "page": 0 }));
    let entry = listed["result"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["rid"] == quarantined[0].to_string())
        .unwrap()
        .clone();
    let reply = radicled.call(
        "rad.remove_repo",
        json!({ "rid": entry["rid"], "qid": entry["qid"] }),
    );
    assert_eq!(reply["result"], json!({ "removed": true }), "{reply}");
    assert_eq!(stats(&mut radicled)["quarantined_count"], 2);
    // A removal that finds nothing to remove changes nothing.
    let reply = radicled.call(
        "rad.remove_repo",
        json!({ "rid": entry["rid"], "qid": entry["qid"] }),
    );
    assert_eq!(code(&reply), "not_quarantined", "{reply}");
    assert_eq!(stats(&mut radicled)["quarantined_count"], 2);

    // An online repair that quarantines its repository.
    let reply = radicled.call(
        "rad.write",
        json!({
            "op": "comment_issue",
            "args": { "rid": broken.to_string(), "issue_id": "abcdef0123", "body": "Nowhere." },
        }),
    );
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(
        "an online repair quarantined its repository",
        Duration::from_secs(30)
    ));
    stats_until(&mut radicled, |r| r["quarantined_count"] == 3);
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// 0008, "The address policy" and 0007's NAT64 stats: discovery's state and
/// why its resolvers failed, cut to the first 16 whatever the OS lists;
/// `socks5` mode runs no discovery.
#[test]
fn nat64_is_reported_in_direct_mode_and_its_failures_are_cut() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    // Twenty resolvers that can't be asked: the first 8 are each a
    // failure, the 12 past the round's 8 each another.
    let names: Vec<String> = (1..=20).map(|n| format!("unaskable-{n}")).collect();
    let listed = names.join(",");
    let mut radicled = Radicled::serve(
        &dirs,
        &[("FREEDOM_RADICLED_TEST_NAT64_RESOLVERS", listed.as_str())],
    );
    assert!(radicled.start()["result"].is_object());
    let result = stats_until(&mut radicled, |r| {
        r["network"]["nat64"]["state"] == "unknown"
            && r["network"]["nat64"]["failures"]
                .as_array()
                .is_some_and(|failures| !failures.is_empty())
    });
    let mut failures = vec!["unaskable"; 8];
    failures.extend(vec!["over_limit"; 8]);
    assert_eq!(
        result["network"],
        json!({ "mode": "direct", "nat64": { "state": "unknown", "prefixes": [], "failures": failures } })
    );
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));

    // A proxy on loopback that nothing serves.
    let mut radicled = Radicled::serve_on(&dirs, "socks5:127.0.0.1:9", &[]);
    assert!(radicled.start()["result"].is_object());
    let result = stats_until(&mut radicled, |r| r["connected_peers"].is_u64());
    assert_eq!(result["node"], "running", "{result}");
    assert_eq!(
        result["network"],
        json!({ "mode": "socks5", "nat64": null })
    );
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// The node's thread ended while it should run: `down`, not alive, and
/// nothing of the node reported, until the process ends with 70.
#[test]
fn a_node_down_is_reported_down() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_STOP_NODE", "1"),
            ("FREEDOM_RADICLED_TEST_HOLD_DOWN", "1"),
        ],
    );
    assert!(radicled.start()["result"].is_object());
    assert!(radicled.logs(
        "test hook: the watch holds the node down",
        Duration::from_secs(20)
    ));
    let result = stats(&mut radicled);
    assert_eq!(result["node"], "down", "{result}");
    assert_eq!(result["node_alive"], false, "{result}");
    assert_eq!(result["connected_peers"], Value::Null, "{result}");
    assert_eq!(result["network"]["nat64"], Value::Null, "{result}");
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(70));
}

/// The watch's look at the peers holds the node shared: a stop that meets
/// one waits for it, in its time, so the node is asked with nothing
/// holding it and the stop is clean; one that outlives the stop's time
/// leaves the stop unproven, the marker kept, within the exit.
#[test]
fn the_stop_waits_for_the_watchs_look_in_its_time() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_LOOK", "1500")]);
    assert!(radicled.start()["result"].is_object());
    assert!(radicled.logs(LOOK_HOLDS, Duration::from_secs(20)));
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);

    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_LOOK", "20000"),
            ("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS", "1000"),
        ],
    );
    assert!(radicled.start()["result"].is_object());
    assert!(radicled.logs(LOOK_HOLDS, Duration::from_secs(20)));
    let stopped = Instant::now();
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert!(stopped.elapsed() < Duration::from_secs(8));
    let log = radicled.stderr();
    assert!(log.contains("the node didn't stop cleanly"), "{log}");
    assert!(
        log.contains("the node's watch was still counting its peers"),
        "{log}"
    );
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}
