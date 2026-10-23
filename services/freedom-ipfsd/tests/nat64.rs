//! `direct`'s address table and NAT64 discovery, through the binary (design
//! 0007, "Network-specific NAT64 prefixes", "Configured targets" and
//! "Stats"):
//!
//! - **The table is on under `direct`:** an untrusted provider on loopback
//!   is refused before any connection; the same provider, as a configured
//!   target (its host and port a delegated router's), is reached.
//! - **`ipfs.stats`'s `network`** reports the mode and, under `direct`,
//!   what discovery knows: the state, the prefixes learned, and why the
//!   resolvers that failed did, each a fixed name. Under `socks5`, `nat64`
//!   is null.
//! - **Discovery runs while a `direct` instance lives:** a process with
//!   only `socks5` instances, or none, sends no query, and a pause sends no
//!   refresh.
//!
//! Each process asks only the test's resolvers, on loopback
//! (`FREEDOM_IPFSD_TEST_NAT64_RESOLVERS`).

#![cfg(feature = "testhooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{Record, RecordData};
use serde_json::{Value, json};

/// Blocks nobody has.
const ABSENT: &str = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";
const OTHER_ABSENT: &str = "bafkreibtv6fpuyxz7zkalsiyejp74o4yrn6vybrsssx2bo4rdtag56y54u";

/// A DNS64 resolver on loopback: it answers each query with AAAA records
/// for `ipv4only.arpa` under its prefixes (a /96 each, TTL 5 s), or with
/// SERVFAIL while `failing`, and counts the queries.
struct Dns64 {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

impl Dns64 {
    fn start(prefixes: &[&str], failing: bool) -> Dns64 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let counted = queries.clone();
        let records: Vec<Ipv6Addr> = prefixes
            .iter()
            .map(|prefix| {
                let mut segments = prefix.parse::<Ipv6Addr>().unwrap().segments();
                // 192.0.0.170, at /96's place.
                segments[6] = 0xc000;
                segments[7] = 0x00aa;
                Ipv6Addr::from(segments)
            })
            .collect();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            while let Ok((read, from)) = socket.recv_from(&mut buffer) {
                counted.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = Message::from_vec(&buffer[..read]) else {
                    continue;
                };
                let mut reply = Message::new();
                reply
                    .set_id(query.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(query.op_code())
                    .set_recursion_desired(true)
                    .set_recursion_available(true)
                    .set_response_code(if failing {
                        ResponseCode::ServFail
                    } else {
                        ResponseCode::NoError
                    });
                for question in query.queries() {
                    reply.add_query(question.clone());
                    if !failing {
                        for addr in &records {
                            reply.add_answer(Record::from_rdata(
                                question.name().clone(),
                                5,
                                AAAA(*addr).into_rdata(),
                            ));
                        }
                    }
                }
                let _ = socket.send_to(&reply.to_vec().unwrap(), from);
            }
        });
        Dns64 { addr, queries }
    }

    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

fn network_stats(ipfsd: &mut Ipfsd, instance: &str) -> Value {
    let reply = ipfsd.call("ipfs.stats", json!({ "instance": instance }));
    reply["result"]["network"].clone()
}

/// `network_stats` until `done` holds, or 10 s.
fn network_stats_until(ipfsd: &mut Ipfsd, instance: &str, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let network = network_stats(ipfsd, instance);
        if done(&network) || Instant::now() > deadline {
            return network;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `--network` for a proxy on a closed port: an instance under it starts,
/// since nothing is sent at start.
fn socks5_closed() -> String {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    socks5(closed)
}

/// A private instance for a `socks5` process: delegated routing.
fn socks5_instance(id: &str) -> Value {
    let mut params = memory(id);
    params["routing"]["mode"] = json!("delegated");
    params
}

#[test]
fn direct_refuses_an_untrusted_provider_on_loopback_and_reaches_a_configured_one() {
    // Each block's one provider, as the store records it: the untrusted
    // one, and one whose host and port are a delegated router's.
    let (untrusted, configured) = (Server::start(), Server::start());
    let dirs = Dirs::new();
    seed_provider(&dirs, &[ABSENT.to_string()], &untrusted);
    seed_provider(&dirs, &[OTHER_ABSENT.to_string()], &configured);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    ipfsd.hello();
    let mut params = disk("p-1");
    params["routing"]["delegated_routers"] = json!([
        "https://delegated-ipfs.dev/routing/v1",
        format!("http://127.0.0.1:{}/routing/v1", configured.port),
    ]);
    assert_eq!(ipfsd.start(params)["result"]["instance"], "p-1");

    // Untrusted: refused before any connection.
    let mut request = get("p-1", &format!("/ipfs/{ABSENT}"));
    request["headers_ms"] = json!(3000);
    let reply = ipfsd.call("ipfs.request", request);
    let status = reply["result"]["status"].as_u64().unwrap_or(0);
    assert!(matches!(status, 502 | 504), "{reply}");
    assert_eq!(untrusted.accepted(), 0, "the refused provider was reached");

    // Configured: exempt, as configured targets are, loopback included.
    // It never answers, so the request ends at its deadline.
    let mut request = get("p-1", &format!("/ipfs/{OTHER_ABSENT}"));
    request["headers_ms"] = json!(3000);
    ipfsd.call("ipfs.request", request);
    assert!(
        configured.accepted() > 0,
        "the configured provider wasn't reached"
    );
    assert_eq!(untrusted.accepted(), 0);
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn stats_report_what_discovery_knows_under_direct_and_nothing_under_socks5() {
    let dns64 = Dns64::start(&["2001:db8:64::"], false);
    let resolvers = dns64.addr.to_string();
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS", &resolvers)]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    let network = network_stats_until(&mut ipfsd, "e-1", |network| {
        network["nat64"]["state"] == "known"
    });
    assert_eq!(
        network,
        json!({ "mode": "direct", "nat64": {
            "state": "known", "prefixes": ["2001:db8:64::/96"], "failures": [] } })
    );
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    // A `socks5` process learns nothing.
    let mut ipfsd = Ipfsd::ephemeral_on(
        &socks5_closed(),
        &[("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS", &resolvers)],
    );
    ipfsd.hello();
    assert_eq!(
        ipfsd.start(socks5_instance("e-2"))["result"]["instance"],
        "e-2"
    );
    assert_eq!(
        network_stats(&mut ipfsd, "e-2"),
        json!({ "mode": "socks5", "nat64": null })
    );
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));

    // A resolver that fails, and one that can't be asked (a link-local
    // address with no interface): unknown, and why, by fixed names only.
    let failing = Dns64::start(&[], true);
    let resolvers = format!("{},fe80::1", failing.addr);
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS", &resolvers)]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    // Unknown as soon as the round begins (the unaskable one), then with
    // both reasons once the failing one has answered.
    let network = network_stats_until(&mut ipfsd, "e-1", |network| {
        network["nat64"]["failures"]
            .as_array()
            .is_some_and(|failures| failures.len() == 2)
    });
    assert_eq!(
        network,
        json!({ "mode": "direct", "nat64": {
            "state": "unknown", "prefixes": [], "failures": ["unaskable", "rcode"] } })
    );
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn discovery_queries_only_while_a_direct_instance_lives() {
    let dns64 = Dns64::start(&["2001:db8:64::"], false);
    let resolvers = dns64.addr.to_string();
    // A `socks5` process, with an instance: no query.
    let mut ipfsd = Ipfsd::ephemeral_on(
        &socks5_closed(),
        &[("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS", &resolvers)],
    );
    ipfsd.hello();
    assert_eq!(
        ipfsd.start(socks5_instance("e-1"))["result"]["instance"],
        "e-1"
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(dns64.queries(), 0, "a query with no direct instance");
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));

    // A `direct` one: discovery runs while an instance lives.
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS", &resolvers)]);
    ipfsd.hello();
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(dns64.queries(), 0, "a query with no instance");
    assert_eq!(ipfsd.start(memory("e-2"))["result"]["instance"], "e-2");
    let network = network_stats_until(&mut ipfsd, "e-2", |network| {
        network["nat64"]["state"] == "known"
    });
    assert_eq!(network["nat64"]["state"], "known", "{network}");
    assert!(dns64.queries() > 0);

    // It stops: paused, and the 5 s refresh sends nothing.
    assert_eq!(ipfsd.stop("e-2")["result"], json!({ "instance": "e-2" }));
    let paused = Arc::new(Mutex::new(dns64.queries()));
    std::thread::sleep(Duration::from_millis(6500));
    assert_eq!(
        dns64.queries(),
        *paused.lock().unwrap(),
        "a refresh while paused"
    );

    // Another `direct` instance resumes it, pending until its round.
    assert_eq!(ipfsd.start(memory("e-3"))["result"]["instance"], "e-3");
    let network = network_stats_until(&mut ipfsd, "e-3", |network| {
        network["nat64"]["state"] == "known"
    });
    assert_eq!(network["nat64"]["prefixes"], json!(["2001:db8:64::/96"]));
    assert!(dns64.queries() > *paused.lock().unwrap());
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

/// 169-M1: a fenced instance's discovery lease goes at its fence, not when
/// its teardown is proven. A live instance's stop, its teardown held 2 s
/// across the 5 s refresh: no query until the stop's acknowledgement.
#[test]
fn a_stopped_instance_holds_discovery_no_longer_than_its_fence() {
    let dns64 = Dns64::start(&["2001:db8:64::"], false);
    let resolvers = dns64.addr.to_string();
    let mut ipfsd = Ipfsd::ephemeral(&[
        ("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS", &resolvers),
        ("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN_MS", "2000"),
    ]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    let network = network_stats_until(&mut ipfsd, "e-1", |network| {
        network["nat64"]["state"] == "known"
    });
    assert_eq!(network["nat64"]["state"], "known", "{network}");
    // Past 4 s of the 5 s TTL, the stop; its teardown is held past the
    // refresh's time.
    std::thread::sleep(Duration::from_millis(4000));
    let before = dns64.queries();
    let stopped = Instant::now();
    assert_eq!(ipfsd.stop("e-1")["result"], json!({ "instance": "e-1" }));
    assert!(stopped.elapsed() >= Duration::from_millis(1500));
    assert_eq!(
        dns64.queries(),
        before,
        "a query during the fenced teardown"
    );
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

/// The same for a start fenced while it builds, by each of a start's
/// fences: a stop, a cancel, its deadline, the connection's end. Fenced 1 s
/// after its admission's query, its build held 5.5 s: past the 5 s
/// refresh, and within the 5 s bound its fence armed. No query meanwhile.
#[test]
fn a_start_fenced_while_building_holds_discovery_no_longer() {
    for fence in ["stop", "cancel", "deadline", "end"] {
        let dns64 = Dns64::start(&["2001:db8:64::"], false);
        let resolvers = dns64.addr.to_string();
        let mut env = vec![
            ("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS", resolvers.as_str()),
            ("FREEDOM_IPFSD_TEST_START_DELAY_MS", "5500"),
        ];
        if fence == "deadline" {
            env.push(("FREEDOM_IPFSD_TEST_START_DEADLINE_MS", "1000"));
        }
        let mut ipfsd = Ipfsd::ephemeral(&env);
        ipfsd.hello();
        let start = ipfsd.request("ipfs.start", memory("e-1"));
        // Its admission took the lease: discovery has asked.
        let deadline = Instant::now() + Duration::from_secs(5);
        while dns64.queries() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(dns64.queries() > 0, "{fence}: no query at admission");
        std::thread::sleep(Duration::from_millis(1000));
        let before = dns64.queries();
        match fence {
            "stop" => {
                let stop = ipfsd.request("ipfs.stop", json!({ "instance": "e-1" }));
                assert_eq!(ipfsd.recv()["id"], start);
                assert_eq!(ipfsd.recv()["id"], stop);
            }
            "cancel" => {
                ipfsd.cancel(start);
                // The instance is gone once built and torn down.
                std::thread::sleep(Duration::from_millis(5500));
            }
            "deadline" => {
                assert_eq!(ipfsd.recv()["error"]["code"], "deadline");
                std::thread::sleep(Duration::from_millis(5500));
            }
            _ => {
                ipfsd.close_stdin();
                assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0), "{fence}");
            }
        }
        assert_eq!(
            dns64.queries(),
            before,
            "{fence}: a query while the fenced start built"
        );
        if fence != "end" {
            ipfsd.close_stdin();
            assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0), "{fence}");
        }
    }
}
