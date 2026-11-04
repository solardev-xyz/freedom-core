//! The process's one DNS configuration, through the binary, confined
//! (design 0010, "Name resolution through glibc"; freedom-ipfs #82): read
//! once the process is confined, and asked by every lookup an instance
//! makes, so `confinement.resolution` names what resolves.
//!
//! A fixture DNS server answers two names, and only it does: Cloudflare's
//! resolvers, the built-in fallback, answer `.example` names with NXDOMAIN.
//! - **An HTTP lookup:** the instance's delegated router is named
//!   `router.system-dns.example`, which the gate's HTTP resolver looks up.
//! - **A `/dns4` dial:** the router names a Bitswap provider at
//!   `/dns4/peer.system-dns.example/tcp/<port>/ws`, which is dialed by
//!   name: libp2p's DNS layer looks it up. The fixture answers 127.0.0.1,
//!   which the address table then refuses, as it would a real provider's:
//!   the canary there is never dialed. (With the table off, a testhook, the
//!   gate has no resolver of its own, and HTTP lookups would be the
//!   system's `getaddrinfo`: the table stays on.)
//!
//! A provider's other `/dns*` names (TCP, QUIC) and DNSLink go to the DoH
//! endpoint `ipfs.start` names, as design 0007 has them: a configured
//! target, whose own name resolves through this configuration. They aren't
//! the system's lookups, and `resolution` doesn't describe them.
//!
//! The fixture resolv.conf lives in the data directory, which the process
//! may read confined (`FREEDOM_IPFSD_TEST_RESOLV_CONF`). Its nameserver is
//! asked on the fixture's port (`FREEDOM_IPFSD_TEST_DNS_PORT`), since a
//! resolv.conf names no port. A malformed file and a missing one are the
//! fallback: reported with the reason, and the fixture is never asked.
//! Unix: Windows reads its configuration from the system, not a file.

#![cfg(all(unix, feature = "testhooks"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Record, RecordData, RecordType};
use serde_json::{Value, json};

const ROUTER: &str = "router.system-dns.example";
const PEER_NAME: &str = "peer.system-dns.example";
/// A peer ID; the canary never completes a handshake as it.
const PEER: &str = "12D3KooWAC7ALVECw2xQHccT3hSUcQU7pJ3hvwV77w1kEevC5kKG";
/// The resolv.conf's search domain: names are looked up as written, so no
/// query names it.
const SEARCH: &str = "corp.example";
/// A block nobody has: its lookup goes to the router.
const ABSENT: &str = "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";

/// A DNS server on a loopback UDP port: `A` records for [`ROUTER`] and
/// [`PEER_NAME`] (127.0.0.1), no data for their other types, NXDOMAIN for
/// any other name. It records every query's name.
struct Dns {
    port: u16,
    queries: Arc<Mutex<Vec<String>>>,
}

impl Dns {
    fn start() -> Dns {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let recorded = queries.clone();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            while let Ok((read, from)) = socket.recv_from(&mut buffer) {
                let Ok(query) = Message::from_vec(&buffer[..read]) else {
                    continue;
                };
                let mut reply = Message::new();
                reply
                    .set_id(query.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(query.op_code())
                    .set_recursion_desired(true)
                    .set_recursion_available(true);
                for question in query.queries() {
                    let name = question.name().to_ascii();
                    let name = name.trim_end_matches('.').to_ascii_lowercase();
                    recorded
                        .lock()
                        .unwrap()
                        .push(format!("{name} {}", question.query_type()));
                    reply.add_query(question.clone());
                    if name != ROUTER && name != PEER_NAME {
                        reply.set_response_code(ResponseCode::NXDomain);
                    } else if question.query_type() == RecordType::A {
                        reply.add_answer(Record::from_rdata(
                            question.name().clone(),
                            5,
                            A(Ipv4Addr::LOCALHOST).into_rdata(),
                        ));
                    }
                }
                let _ = socket.send_to(&reply.to_vec().unwrap(), from);
            }
        });
        Dns { port, queries }
    }

    fn queries(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }

    fn asked(&self, name: &str) -> bool {
        self.queries()
            .iter()
            .any(|query| query.split(' ').next() == Some(name))
    }
}

/// A listener that counts its connections. With `body`, it answers each
/// request on them with it, as a delegated router's JSON; without, it holds
/// them (the canary).
struct Listener {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl Listener {
    fn start(body: Option<String>) -> Listener {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = accepted.clone();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                counted.fetch_add(1, Ordering::SeqCst);
                let Ok(mut stream) = stream else { continue };
                let Some(body) = body.clone() else {
                    held.push(stream);
                    continue;
                };
                std::thread::spawn(move || {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        Listener { addr, accepted }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// A router naming one Bitswap provider for every CID: [`PEER`] at
/// `/dns4/<PEER_NAME>/tcp/<canary's port>/ws`.
fn router(canary: &Listener) -> Listener {
    let provider = json!({ "Providers": [{
        "Schema": "peer",
        "ID": PEER,
        "Addrs": [format!("/dns4/{PEER_NAME}/tcp/{}/ws", canary.addr.port())],
        "Protocols": ["transport-bitswap"],
    }] });
    Listener::start(Some(provider.to_string()))
}

fn wait_for(timeout: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

/// The persistent process with `resolv_conf` (written into its data
/// directory, unless `None`: a file that isn't there), its nameservers on
/// the fixture's port, and the address table on.
fn spawn(dirs: &Dirs, resolv_conf: Option<&str>, dns: &Dns) -> Ipfsd {
    std::fs::create_dir_all(&dirs.data).unwrap();
    let path = dirs.data.join("resolv.conf");
    if let Some(text) = resolv_conf {
        std::fs::write(&path, text).unwrap();
    }
    let path = path.to_str().unwrap().to_string();
    let port = dns.port.to_string();
    Ipfsd::persistent(
        dirs,
        &[
            ("FREEDOM_IPFSD_TEST_RESOLV_CONF", &path),
            ("FREEDOM_IPFSD_TEST_DNS_PORT", &port),
        ],
    )
}

/// An instance whose delegated router is `router`, by name.
fn instance(id: &str, router: &Listener) -> Value {
    let mut params = disk(id);
    params["routing"]["mode"] = json!("delegated");
    params["routing"]["delegated_routers"] =
        json!([format!("http://{ROUTER}:{}/routing/v1", router.addr.port())]);
    params
}

fn request(id: &str) -> Value {
    let mut params = get(id, ABSENT);
    params["headers_ms"] = json!(10_000);
    params
}

#[test]
fn every_lookup_asks_the_resolv_conf_the_report_names() {
    let dns = Dns::start();
    let canary = Listener::start(None);
    let router = router(&canary);
    let dirs = Dirs::new();
    let mut ipfsd = spawn(
        &dirs,
        Some(&format!("search {SEARCH}\nnameserver 127.0.0.1\n")),
        &dns,
    );
    let hello = ipfsd.hello();
    let confinement = &hello["result"]["confinement"];
    assert_eq!(confinement["resolution"], "resolv_conf", "{confinement}");
    assert!(
        confinement["reasons"].get("resolution").is_none(),
        "{confinement}"
    );

    let started = ipfsd.start(instance("p-1", &router));
    assert_eq!(started["result"]["instance"], "p-1", "{started}");
    let id = ipfsd.request("ipfs.request", request("p-1"));
    // The router's name, through the gate's HTTP resolver; then the
    // provider's `/dns4` name, through libp2p's DNS layer.
    let reached = wait_for(Duration::from_secs(10), || {
        dns.asked(ROUTER) && router.accepted() > 0 && dns.asked(PEER_NAME)
    });
    let queries = dns.queries();
    // On a failure, what the instance did: its progress events' phases and
    // errors.
    let progress = if reached {
        String::new()
    } else {
        let stats = ipfsd.call("ipfs.stats", json!({ "instance": "p-1" }));
        stats["result"]["progress"]["events"]
            .as_array()
            .map(|events| {
                events
                    .iter()
                    .map(|e| {
                        format!(
                            "{} {} {}",
                            e["raw_phase"], e["last_error_code"], e["last_error_message"]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|| stats.to_string())
    };
    assert!(
        dns.asked(ROUTER),
        "the router's name wasn't asked: {queries:?}\n{progress}"
    );
    assert!(
        router.accepted() > 0,
        "the router wasn't reached: {queries:?}\n{progress}"
    );
    assert!(
        dns.asked(PEER_NAME),
        "the /dns4 name wasn't asked: {queries:?}\n{progress}"
    );
    // Its answer is loopback, which the address table refuses.
    assert_eq!(canary.accepted(), 0, "a loopback provider was dialed");
    // Every name as written: none with the search domain.
    assert!(
        queries.iter().all(|query| !query.contains(SEARCH)),
        "{queries:?}"
    );
    ipfsd.cancel(id);
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn a_resolv_conf_that_cant_be_used_is_reported_as_the_fallback_and_never_asked() {
    for (resolv_conf, cause) in [
        (
            Some("nameserver not-an-address\nnameserver 127.0.0.1\n"),
            "couldn't be parsed",
        ),
        (None, "couldn't be read"),
    ] {
        let dns = Dns::start();
        let canary = Listener::start(None);
        let router = router(&canary);
        let dirs = Dirs::new();
        let mut ipfsd = spawn(&dirs, resolv_conf, &dns);
        let hello = ipfsd.hello();
        let confinement = &hello["result"]["confinement"];
        assert_eq!(confinement["resolution"], "fallback", "{confinement}");
        let why = confinement["reasons"]["resolution"].as_str().unwrap_or("");
        assert!(
            why.contains(cause) && why.contains("built-in servers"),
            "{confinement}"
        );

        // The router's name goes to the built-in servers, which don't know
        // it: the fixture hears nothing, and the router isn't reached.
        ipfsd.start(instance("p-1", &router));
        let id = ipfsd.request("ipfs.request", request("p-1"));
        let reply = ipfsd.reply(id);
        assert!(reply.is_object(), "{reply}");
        assert!(dns.queries().is_empty(), "{:?}", dns.queries());
        assert_eq!(router.accepted(), 0);
        assert_eq!(canary.accepted(), 0);
        ipfsd.shutdown();
        assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    }
}
