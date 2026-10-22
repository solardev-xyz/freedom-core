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

/// A private instance under `socks5`, to a proxy on a closed port: it
/// starts, since nothing is sent at start.
fn socks5_instance(id: &str) -> Value {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut params = memory(id);
    params["routing"]["mode"] = json!("delegated");
    params["network"] = json!({ "mode": "socks5", "ip": "127.0.0.1", "port": closed.port() });
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
    let network = network_stats_until(&mut ipfsd, "e-1", |network| {
        network["nat64"]["state"] == "unknown"
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
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS", &resolvers)]);
    ipfsd.hello();

    // A `socks5` instance alone: no query.
    assert_eq!(
        ipfsd.start(socks5_instance("e-1"))["result"]["instance"],
        "e-1"
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(dns64.queries(), 0, "a query with no direct instance");

    // A `direct` one: discovery runs.
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
