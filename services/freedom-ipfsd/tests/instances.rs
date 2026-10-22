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
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();
    // `socks5` takes delegated or offline routing only (decision D6).
    let mut socks = memory("e-1");
    socks["network"] = json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9150 });
    socks["routing"]["mode"] = json!("auto");
    let reply = ipfsd.start(socks);
    assert_eq!(reply["error"]["code"], "invalid_argument");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("socks5"),
        "{reply}"
    );
    for (pointer, value) in [
        ("/network/mode", json!("tor")),
        (
            "/network",
            json!({ "mode": "socks5", "ip": "localhost", "port": 9150 }),
        ),
        (
            "/network",
            json!({ "mode": "socks5", "ip": "0.0.0.0", "port": 9150 }),
        ),
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
    // `socks5` with offline routing starts: nothing is sent at start, so
    // the proxy needn't be up.
    let mut socks = memory("e-2");
    socks["network"] = json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9 });
    assert_eq!(ipfsd.start(socks)["result"]["instance"], "e-2");
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
    let mut ipfsd = Ipfsd::persistent(&dirs, &[("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN_MS", "1500")]);
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

    let sent = Instant::now();
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
    // Then the stop, once the runtime's join has waited for the held job.
    let reply = ipfsd.recv();
    assert_eq!(reply["id"], stop, "{reply}");
    assert_eq!(reply["result"], json!({ "instance": "p-1" }));
    assert!(sent.elapsed() >= Duration::from_millis(1500));
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
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN_MS", "8000")]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    let sent = Instant::now();
    ipfsd.request("ipfs.stop", json!({ "instance": "e-1" }));
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(70));
    // At the bound, before the held job would have let the join return.
    let took = sent.elapsed();
    assert!(
        took >= Duration::from_secs(5) && took < Duration::from_secs(8),
        "{took:?}"
    );
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
    let mut ipfsd = Ipfsd::persistent(&dirs, &[("FREEDOM_IPFSD_TEST_START_DELAY_MS", "500")]);
    ipfsd.hello();
    let start = ipfsd.request("ipfs.start", disk("p-1"));
    let stop = ipfsd.request("ipfs.stop", json!({ "instance": "p-1" }));
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
}

#[cfg(feature = "testhooks")]
#[test]
fn a_cancelled_start_is_torn_down() {
    let dirs = Dirs::new();
    let mut ipfsd = Ipfsd::persistent(&dirs, &[("FREEDOM_IPFSD_TEST_START_DELAY_MS", "500")]);
    ipfsd.hello();
    let start = ipfsd.request("ipfs.start", disk("p-1"));
    ipfsd.cancel(start);
    assert_eq!(ipfsd.reply(start)["error"]["code"], "cancelled");
    // Its room stays taken until it is built and torn down.
    assert_eq!(ipfsd.start(disk("p-2"))["error"]["code"], "busy");
    let deadline = Instant::now() + Duration::from_secs(10);
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
}

#[cfg(feature = "testhooks")]
#[test]
fn a_start_past_its_deadline_is_answered_deadline_and_torn_down() {
    let mut ipfsd = Ipfsd::ephemeral(&[
        ("FREEDOM_IPFSD_TEST_START_DELAY_MS", "800"),
        ("FREEDOM_IPFSD_TEST_START_DEADLINE_MS", "100"),
    ]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["error"]["code"], "deadline");
    // Fenced at the deadline.
    assert_eq!(ipfsd.stop("e-1")["error"]["code"], "stopped");
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    // The end waited for the build, then tore the instance down.
    let stderr = ipfsd.stderr();
    assert!(stderr.contains("\"instance stopped\""), "{stderr}");
}

/// Review of #129, M1: a start fenced while its build is held past the 5 s
/// bound. The bound runs from the fence, through the build: the process
/// exits 70 at it, with nothing answered after the fence, rather than when
/// the build (8 s) ends.
#[cfg(feature = "testhooks")]
fn a_fenced_build_held_past_5_s_exits_70(
    env: &[(&str, &str)],
    fence: impl FnOnce(&mut Ipfsd, u64),
    after: Duration,
) {
    let mut ipfsd =
        Ipfsd::ephemeral(&[&[("FREEDOM_IPFSD_TEST_START_DELAY_MS", "8000")], env].concat());
    ipfsd.hello();
    let sent = Instant::now();
    let start = ipfsd.request("ipfs.start", memory("e-1"));
    fence(&mut ipfsd, start);
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(70));
    let took = sent.elapsed();
    assert!(
        took >= after + Duration::from_secs(5) && took < Duration::from_secs(8),
        "{took:?}"
    );
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
