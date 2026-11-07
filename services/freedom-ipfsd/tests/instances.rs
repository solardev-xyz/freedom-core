//! Instances through the binary (design 0007, "Instances and their
//! teardown", "Instance IDs" and "Methods"): `ipfs.start` and `ipfs.stop`
//! in both kinds of process, IDs never reused, and the teardown proven
//! before a stop is answered. Routing is offline throughout: no test
//! touches the network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[cfg(feature = "testhooks")]
use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

#[test]
fn a_persistent_instance_starts_and_stops() {
    let dirs = Dirs::new();
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    ipfsd.hello();
    assert_eq!(
        ipfsd.start(disk("p-1"))["result"],
        json!({ "instance": "p-1" })
    );
    // The add-on's store, in the data directory.
    assert!(dirs.data.join("freedom-ipfs.sqlite3").is_file());
    // One disk instance at a time. Refused starts take no ID.
    assert_eq!(
        ipfsd.start(disk("p-2"))["error"]["code"],
        "invalid_argument"
    );
    assert_eq!(
        ipfsd.start(memory("p-2"))["error"]["code"],
        "invalid_argument"
    );

    assert_eq!(ipfsd.stop("p-1")["result"], json!({ "instance": "p-1" }));
    // Retired, or never seen: `stopped`.
    assert_eq!(ipfsd.stop("p-1")["error"]["code"], "stopped");
    assert_eq!(ipfsd.stop("p-9")["error"]["code"], "stopped");
    // Never reused.
    assert_eq!(
        ipfsd.start(disk("p-1"))["error"]["code"],
        "invalid_argument"
    );
    // A replacement over the same store.
    assert_eq!(
        ipfsd.start(disk("p-2"))["result"],
        json!({ "instance": "p-2" })
    );
    let reply = ipfsd.call("ipfs.stats", json!({ "instance": "p-2" }));
    assert!(reply["result"]["gateway"].is_object(), "{reply}");
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    assert_eq!(
        stderr.matches("\"instance stopped\"").count(),
        2,
        "{stderr}"
    );
}

#[test]
fn ephemeral_instances() {
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();
    for n in 1..=8 {
        let instance = format!("e-{n}");
        assert_eq!(
            ipfsd.start(memory(&instance))["result"]["instance"],
            instance
        );
    }
    // At most 8.
    assert_eq!(ipfsd.start(memory("e-9"))["error"]["code"], "busy");
    // Memory stores only, of at most 32 MiB.
    assert_eq!(
        ipfsd.start(disk("e-10"))["error"]["code"],
        "invalid_argument"
    );
    let large = start_params(
        "e-10",
        json!({ "kind": "memory", "max_bytes": (32 << 20) + 1 }),
    );
    assert_eq!(ipfsd.start(large)["error"]["code"], "invalid_argument");
    // A stop frees room; the refused e-9 took no ID.
    assert_eq!(ipfsd.stop("e-3")["result"], json!({ "instance": "e-3" }));
    assert_eq!(ipfsd.start(memory("e-9"))["result"]["instance"], "e-9");
    assert_eq!(
        ipfsd.start(memory("e-3"))["error"]["code"],
        "invalid_argument"
    );
    assert_eq!(ipfsd.stop("e-3")["error"]["code"], "stopped");
    // EOF tears down all 8.
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    assert_eq!(
        stderr.matches("\"instance stopped\"").count(),
        9,
        "{stderr}"
    );
}

#[test]
fn start_params_are_checked() {
    // In a `socks5` process, delegated or offline routing only (decision
    // D6); offline starts, since nothing is sent at start, so the proxy
    // needn't be up.
    let mut socks = Ipfsd::ephemeral_on("socks5:127.0.0.1:9", &[]);
    socks.hello();
    let mut auto = memory("e-1");
    auto["routing"]["mode"] = json!("auto");
    let reply = socks.start(auto);
    assert_eq!(reply["error"]["code"], "invalid_argument");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("socks5"),
        "{reply}"
    );
    assert_eq!(socks.start(memory("e-2"))["result"]["instance"], "e-2");
    socks.close_stdin();
    assert_eq!(socks.exit_code(EXIT_TIMEOUT), Some(0));

    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();
    // The policy is the process's (`--network`): `ipfs.start` can't carry it.
    let mut network = memory("e-1");
    network["network"] = json!({ "mode": "direct" });
    assert_eq!(ipfsd.start(network)["error"]["code"], "invalid_argument");
    for (pointer, value) in [
        (
            "/routing/doh_endpoint",
            json!("https://u@cloudflare-dns.com/"),
        ),
        // `direct` reaches no onion.
        (
            "/routing/delegated_routers",
            json!(["https://router.onion/routing/v1"]),
        ),
        ("/routing/mode", json!("everything")),
        ("/routing/dht_query_timeout_s", json!(0)),
        ("/gateway/max_concurrent_requests", json!(0)),
        ("/store/kind", json!("file")),
        ("/instance", json!("e 1")),
    ] {
        let mut params = memory("e-1");
        *params.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            ipfsd.start(params)["error"]["code"],
            "invalid_argument",
            "{pointer}"
        );
    }
    assert_eq!(
        ipfsd.call("ipfs.start", json!([]))["error"]["code"],
        "invalid_argument"
    );
    assert_eq!(
        ipfsd.call("ipfs.stop", json!({ "instance": 1 }))["error"]["code"],
        "invalid_argument"
    );
    // None of them took e-1.
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn a_store_that_wont_open_is_storage() {
    let dirs = Dirs::new();
    // A directory where the store's file should be.
    std::fs::create_dir_all(dirs.data.join("freedom-ipfs.sqlite3")).unwrap();
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    ipfsd.hello();
    let reply = ipfsd.start(disk("p-1"));
    assert_eq!(reply["error"]["code"], "storage", "{reply}");
    assert_eq!(reply["error"]["data"]["kind"], "store_open", "{reply}");
    // The admitted start took its ID; its room is free again.
    assert_eq!(
        ipfsd.start(disk("p-1"))["error"]["code"],
        "invalid_argument"
    );
    assert_eq!(ipfsd.start(disk("p-2"))["error"]["code"], "storage");
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    let data = dirs.data.to_string_lossy();
    assert!(!stderr.contains(data.as_ref()), "{stderr}");
}

#[cfg(feature = "testhooks")]
#[test]
fn a_stop_is_answered_only_once_quiescence_is_proven() {
    let dirs = Dirs::new();
    let file = dirs.data.join("release");
    let held = hold("until", &file);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN", &held)]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    // The instance's runtime threads, once they have named themselves.
    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        while ipfsd.threads("ipfs-inst-1") == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(ipfsd.threads("ipfs-inst-1") > 0);
    }

    let stop = ipfsd.request("ipfs.stop", json!({ "instance": "p-1" }));
    // The fence comes first: a second stop is `stopped`, and a replacement
    // waits for the room, both answered while the teardown runs.
    let again = ipfsd.request("ipfs.stop", json!({ "instance": "p-1" }));
    let replacement = ipfsd.request("ipfs.start", disk("p-2"));
    let first = ipfsd.recv();
    let second = ipfsd.recv();
    assert_eq!(first["id"], again, "{first}");
    assert_eq!(first["error"]["code"], "stopped", "{first}");
    assert_eq!(second["id"], replacement, "{second}");
    assert_eq!(second["error"]["code"], "busy", "{second}");
    // The instance is cancelled, and its runtime's join waits for the held
    // job: the stop isn't answered.
    ipfsd.logged(TEARDOWN_HELD);
    assert!(ipfsd.quiet_for(Duration::from_millis(300)));
    // Then the stop, once the test releases the job and the join returns.
    release(&file);
    let reply = ipfsd.recv();
    assert_eq!(reply["id"], stop, "{reply}");
    assert_eq!(reply["result"], json!({ "instance": "p-1" }));
    // No thread of the instance's runtime is left.
    #[cfg(target_os = "linux")]
    assert_eq!(ipfsd.threads("ipfs-inst-1"), 0);
    // Its room is free.
    assert_eq!(ipfsd.start(disk("p-2"))["result"]["instance"], "p-2");
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

#[cfg(feature = "testhooks")]
#[test]
fn a_teardown_held_past_5_s_exits_70() {
    // Held until a file the test never creates.
    let never = tempfile::tempdir().unwrap();
    let held = hold("until", &never.path().join("release"));
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN", &held)]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    let sent = Instant::now();
    ipfsd.request("ipfs.stop", json!({ "instance": "e-1" }));
    // At the bound: the held job never lets the join return, before its
    // 30 s, past EXIT_TIMEOUT.
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(70));
    let took = sent.elapsed();
    assert!(took >= Duration::from_secs(5), "{took:?}");
    // The stop was never answered.
    assert!(ipfsd.stdout_closes_within(EXIT_TIMEOUT));
    assert_eq!(ipfsd.leftover(), Vec::<serde_json::Value>::new());
    let stderr = ipfsd.stderr();
    assert!(stderr.contains("teardown_unproven"), "{stderr}");
}

#[cfg(feature = "testhooks")]
#[test]
fn a_stop_while_starting_answers_both() {
    let dirs = Dirs::new();
    let file = dirs.data.join("release");
    let held = hold("after", &file);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[("FREEDOM_IPFSD_TEST_HOLD_START", &held)]);
    ipfsd.hello();
    let start = ipfsd.request("ipfs.start", disk("p-1"));
    // Built, and held before its job looks at its fence: the stop fences a
    // start, and only the teardown is left inside the bound it arms.
    ipfsd.logged(BUILD_RETURNED);
    let stop = ipfsd.request("ipfs.stop", json!({ "instance": "p-1" }));
    // The fence is in place once a second stop is answered `stopped`.
    assert_eq!(ipfsd.stop("p-1")["error"]["code"], "stopped");
    release(&file);
    // The start is fenced: `stopped`. The stop is answered once the
    // instance, built after all, has been torn down.
    let first = ipfsd.recv();
    assert_eq!(first["id"], start, "{first}");
    assert_eq!(first["error"]["code"], "stopped", "{first}");
    let second = ipfsd.recv();
    assert_eq!(second["id"], stop, "{second}");
    assert_eq!(second["result"], json!({ "instance": "p-1" }));
    assert_eq!(
        ipfsd.start(disk("p-1"))["error"]["code"],
        "invalid_argument"
    );
    assert_eq!(ipfsd.start(disk("p-2"))["result"]["instance"], "p-2");
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    assert_eq!(
        stderr.matches("\"instance stopped\"").count(),
        2,
        "{stderr}"
    );
    // Revoked first: p-1 as soon as its job found it fenced; p-2 at the
    // connection's end.
    assert_eq!(
        stopping(&stderr),
        [("p-1".to_string(), true), ("p-2".to_string(), true)],
        "{stderr}"
    );
}

/// Every fence revokes the instance's network first (0007, teardown step
/// 2): a stop's, and the connection's end.
#[test]
fn every_fence_revokes_the_network_first() {
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();
    for instance in ["e-1", "e-2"] {
        assert_eq!(
            ipfsd.start(memory(instance))["result"]["instance"],
            instance
        );
    }
    assert_eq!(ipfsd.stop("e-1")["result"], json!({ "instance": "e-1" }));
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    assert_eq!(
        stopping(&stderr),
        [("e-1".to_string(), true), ("e-2".to_string(), true)],
        "{stderr}"
    );
}

#[cfg(feature = "testhooks")]
#[test]
fn a_cancelled_start_is_torn_down() {
    let dirs = Dirs::new();
    let file = dirs.data.join("release");
    let held = hold("after", &file);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[("FREEDOM_IPFSD_TEST_HOLD_START", &held)]);
    ipfsd.hello();
    let start = ipfsd.request("ipfs.start", disk("p-1"));
    // Built, and held before its job looks at its fence: the cancel fences
    // a start, and only the teardown is left inside the bound it arms.
    ipfsd.logged(BUILD_RETURNED);
    ipfsd.cancel(start);
    assert_eq!(ipfsd.reply(start)["error"]["code"], "cancelled");
    // Its room stays taken until it is torn down. The reader handled the
    // cancel before this start, so the fence is in place.
    assert_eq!(ipfsd.start(disk("p-2"))["error"]["code"], "busy");
    release(&file);
    // A hang guard, not a timing bound.
    let deadline = Instant::now() + READ_TIMEOUT;
    let started = loop {
        let reply = ipfsd.start(disk("p-2"));
        if reply["error"]["code"] != "busy" || Instant::now() >= deadline {
            break reply;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(started["result"]["instance"], "p-2", "{started}");
    assert_eq!(ipfsd.stop("p-1")["error"]["code"], "stopped");
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    // The cancelled start's instance was revoked as soon as its job found
    // it fenced.
    let stderr = ipfsd.stderr();
    assert_eq!(stopping(&stderr)[0], ("p-1".to_string(), true), "{stderr}");
}

#[cfg(feature = "testhooks")]
#[test]
fn a_start_past_its_deadline_is_answered_deadline_and_torn_down() {
    // Held once built, before its job looks at its fence, until the test
    // releases it: its deadline passes meanwhile, or during its build.
    let dirs = Dirs::new();
    let file = dirs.data.join("release");
    let held = hold("after", &file);
    let mut ipfsd = Ipfsd::persistent(
        &dirs,
        &[
            ("FREEDOM_IPFSD_TEST_HOLD_START", &held),
            ("FREEDOM_IPFSD_TEST_START_DEADLINE_MS", "100"),
        ],
    );
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["error"]["code"], "deadline");
    // Fenced at the deadline.
    assert_eq!(ipfsd.stop("p-1")["error"]["code"], "stopped");
    ipfsd.close_stdin();
    // Released once the connection has ended: the exit comes once the
    // instance is torn down.
    ipfsd.logged("the connection ended");
    release(&file);
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    assert!(stderr.contains("\"instance stopped\""), "{stderr}");
}

/// Review of #129, M1: a start fenced while its build is held past the 5 s
/// bound. The bound runs from the fence, through the build: the process
/// exits 70 at it, with nothing answered after the fence, rather than when
/// the build ends. The build is held until a file the test never creates,
/// so it can't end before the hold's 30 s, past EXIT_TIMEOUT.
#[cfg(feature = "testhooks")]
fn a_fenced_build_held_past_5_s_exits_70(
    env: &[(&str, &str)],
    fence: impl FnOnce(&mut Ipfsd, u64),
    after: Duration,
) {
    let never = tempfile::tempdir().unwrap();
    let held = hold("until", &never.path().join("release"));
    let mut ipfsd =
        Ipfsd::ephemeral(&[&[("FREEDOM_IPFSD_TEST_HOLD_START", held.as_str())], env].concat());
    ipfsd.hello();
    let sent = Instant::now();
    let start = ipfsd.request("ipfs.start", memory("e-1"));
    fence(&mut ipfsd, start);
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(70));
    let took = sent.elapsed();
    assert!(took >= after + Duration::from_secs(5), "{took:?}");
    assert!(ipfsd.stdout_closes_within(EXIT_TIMEOUT));
    assert_eq!(ipfsd.leftover(), Vec::<serde_json::Value>::new());
    let stderr = ipfsd.stderr();
    assert!(stderr.contains("teardown_unproven"), "{stderr}");
}

#[cfg(feature = "testhooks")]
#[test]
fn a_stop_while_a_build_is_held_past_5_s_exits_70() {
    a_fenced_build_held_past_5_s_exits_70(
        &[],
        |ipfsd, _| {
            ipfsd.request("ipfs.stop", json!({ "instance": "e-1" }));
        },
        Duration::ZERO,
    );
}

#[cfg(feature = "testhooks")]
#[test]
fn a_cancel_while_a_build_is_held_past_5_s_exits_70() {
    a_fenced_build_held_past_5_s_exits_70(
        &[],
        |ipfsd, start| {
            ipfsd.cancel(start);
            assert_eq!(ipfsd.reply(start)["error"]["code"], "cancelled");
        },
        Duration::ZERO,
    );
}

#[cfg(feature = "testhooks")]
#[test]
fn a_deadline_while_a_build_is_held_past_5_s_exits_70() {
    a_fenced_build_held_past_5_s_exits_70(
        &[("FREEDOM_IPFSD_TEST_START_DEADLINE_MS", "200")],
        |ipfsd, start| {
            assert_eq!(ipfsd.reply(start)["error"]["code"], "deadline");
        },
        Duration::from_millis(200),
    );
}
