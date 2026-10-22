//! `network: { mode: socks5 }` through the binary, against upstream's SOCKS5
//! test proxy (design 0007, "Modes", "Instances and their teardown", and
//! its tests).
//!
//! - **The canary:** advertised in the router's provider records (TCP, QUIC
//!   and an HTTP provider) and, apart, the target of its IPNS redirect, it
//!   sees nothing; the router saw exactly the connections the proxy made to
//!   it, and no datagram. The control, `direct` over the same topology,
//!   reaches both canaries and never the proxy.
//! - **A stop:** once acknowledged, no connection reaches the proxy or the
//!   provider, and the process holds no socket to the proxy.
//! - **Two instances in sequence** keep their own policies.
//! - **An unreachable proxy:** the instance still starts (nothing is sent at
//!   start), and its requests fail 502 or 504, with nothing direct.
//!
//! Each instance is a private one, with delegated routing to a router on
//! loopback, configured by IP literal, which is also its DoH endpoint.
//! Everything stays on loopback.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use freedom_ipfs_net::socks::fixture::{Destination, SocksFixture};
use serde_json::{Value, json};

const PEER: &str = "12D3KooWAC7ALVECw2xQHccT3hSUcQU7pJ3hvwV77w1kEevC5kKG";
const OTHER_PEER: &str = "12D3KooWAtxJkDLacJdK7yZkk2iPp8iMdSVh1bDHzmJ3t8oKUkqA";
/// Blocks nobody has.
const ABSENT: &str = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";
const OTHER_ABSENT: &str = "bafkreibtv6fpuyxz7zkalsiyejp74o4yrn6vybrsssx2bo4rdtag56y54u";

/// Upstream's SOCKS5 test proxy, on a runtime of the test's own.
struct Proxy {
    fixture: SocksFixture,
    _runtime: tokio::runtime::Runtime,
}

impl Proxy {
    fn start() -> Proxy {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let fixture = runtime.block_on(SocksFixture::start());
        Proxy {
            fixture,
            _runtime: runtime,
        }
    }

    fn network(&self) -> Value {
        json!({ "mode": "socks5", "ip": "127.0.0.1", "port": self.fixture.addr().port() })
    }

    fn connects(&self) -> Vec<Destination> {
        self.fixture
            .requests()
            .into_iter()
            .filter(|request| request.is_connect())
            .map(|request| request.destination)
            .collect()
    }
}

/// A TCP listener that counts its connections (and holds them open, or
/// drops them at once), and a UDP socket that counts its datagrams.
struct Canary {
    tcp: SocketAddr,
    udp: SocketAddr,
    accepted: Arc<AtomicUsize>,
    datagrams: Arc<AtomicUsize>,
}

impl Canary {
    /// A canary that drops each connection at once, so a dial fails fast
    /// and the next address is tried.
    fn start() -> Canary {
        Canary::listening(false)
    }

    /// A canary that holds each connection open: a provider that never
    /// answers.
    fn holding() -> Canary {
        Canary::listening(true)
    }

    fn listening(hold: bool) -> Canary {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = accepted.clone();
        let held = Arc::new(Mutex::new(Vec::new()));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counted.fetch_add(1, Ordering::SeqCst);
                if let (true, Ok(stream)) = (hold, stream) {
                    held.lock().unwrap().push(stream);
                }
            }
        });
        let datagrams = Arc::new(AtomicUsize::new(0));
        let udp = count_datagrams(UdpSocket::bind("127.0.0.1:0").unwrap(), &datagrams);
        Canary {
            tcp,
            udp,
            accepted,
            datagrams,
        }
    }

    fn seen(&self) -> (usize, usize) {
        (
            self.accepted.load(Ordering::SeqCst),
            self.datagrams.load(Ordering::SeqCst),
        )
    }
}

fn count_datagrams(socket: UdpSocket, count: &Arc<AtomicUsize>) -> SocketAddr {
    let addr = socket.local_addr().unwrap();
    let counted = count.clone();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        while socket.recv_from(&mut buffer).is_ok() {
            counted.fetch_add(1, Ordering::SeqCst);
        }
    });
    addr
}

/// A delegated router, and the instance's DoH endpoint: it answers every
/// provider lookup with `providers` (a peer and its addresses each), redirects every IPNS lookup to
/// `ipns_redirect` (if given), and answers every DoH question with no
/// answer, so DNSLink, which an IPNS name tries first, moves on. It counts
/// every connection it accepts, those carrying no request included, and
/// every datagram sent to its port.
struct Router {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    datagrams: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
}

impl Router {
    fn start(providers: &[(&str, Vec<String>)], ipns_redirect: Option<SocketAddr>) -> Router {
        let records: Vec<Value> = providers
            .iter()
            .map(|(peer, addrs)| json!({ "Schema": "peer", "ID": peer, "Addrs": addrs }))
            .collect();
        let body = json!({ "Providers": records }).to_string();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let datagrams = Arc::new(AtomicUsize::new(0));
        count_datagrams(
            UdpSocket::bind(addr).expect("the router's port is free over UDP"),
            &datagrams,
        );
        let accepted = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let (counted, recorded) = (accepted.clone(), paths.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counted.fetch_add(1, Ordering::SeqCst);
                let Ok(stream) = stream else { continue };
                let (body, recorded) = (body.clone(), recorded.clone());
                std::thread::spawn(move || serve(stream, &body, ipns_redirect, &recorded));
            }
        });
        Router {
            addr,
            accepted,
            datagrams,
            paths,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn datagrams(&self) -> usize {
        self.datagrams.load(Ordering::SeqCst)
    }

    fn paths(&self) -> Vec<String> {
        self.paths.lock().unwrap().clone()
    }
}

/// One request on `stream`, answered as [`Router`] says.
fn serve(
    mut stream: std::net::TcpStream,
    providers: &str,
    ipns_redirect: Option<SocketAddr>,
    recorded: &Mutex<Vec<String>>,
) {
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
    recorded.lock().unwrap().push(path.clone());
    let (status, location, body) = if path.starts_with("/routing/v1/providers/") {
        ("200 OK", None, providers.to_string())
    } else if path.starts_with("/dns-query") {
        ("200 OK", None, r#"{"Status":3}"#.to_string())
    } else if let (true, Some(to)) = (path.starts_with("/routing/v1/ipns/"), ipns_redirect) {
        (
            "302 Found",
            Some(format!("http://{to}/ipns")),
            String::new(),
        )
    } else {
        ("404 Not Found", None, String::new())
    };
    let location = location
        .map(|location| format!("location: {location}\r\n"))
        .unwrap_or_default();
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status}\r\n{location}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}

/// A private instance with delegated routing to `router` (its DoH endpoint
/// the router's too), under `network`.
fn instance(id: &str, router: &Router, network: Value) -> Value {
    let mut params = memory(id);
    params["routing"]["mode"] = json!("delegated");
    params["routing"]["delegated_routers"] = json!([format!("http://{}/routing/v1", router.addr)]);
    params["routing"]["doh_endpoint"] = json!(format!("http://{}/dns-query", router.addr));
    params["network"] = network;
    params
}

/// The status of a GET for `path` on `instance`.
fn status(ipfsd: &mut Ipfsd, instance: &str, path: &str) -> u64 {
    let id = ipfsd.request("ipfs.request", get(instance, path));
    let reply = ipfsd.reply(id);
    reply["result"]["status"]
        .as_u64()
        .unwrap_or_else(|| panic!("{reply}"))
}

fn wait_for(timeout: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

/// How many TCP sockets in this network namespace still hold a connection
/// to `server`, from `/proc` (Linux): connecting, established, or closed by
/// the server but not yet by their own end (`CLOSE_WAIT`). A socket whose
/// own end has closed (`FIN_WAIT`, `TIME_WAIT`, `LAST_ACK`) doesn't count.
/// An error if the tables can't be read.
///
/// The namespace's tables, not the service's own: fc-service's hardening
/// makes the service non-dumpable, so its `/proc/<pid>/fd` is closed even
/// to its own user. Only the service connects to a test's proxy, so a
/// socket holding a connection to it is the service's.
#[cfg(target_os = "linux")]
fn connections_held_to(server: SocketAddr) -> std::io::Result<usize> {
    // 01 ESTABLISHED, 02 SYN_SENT, 08 CLOSE_WAIT.
    const HELD: [&str; 3] = ["01", "02", "08"];
    let mut held = 0;
    for table in ["tcp", "tcp6"] {
        let text = std::fs::read_to_string(format!("/proc/self/net/{table}"))?;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(remote), Some(state)) = (fields.get(2), fields.get(3)) else {
                continue;
            };
            if HELD.contains(state) && proc_net_address(remote) == Some(server) {
                held += 1;
            }
        }
    }
    Ok(held)
}

/// An address as `/proc/net/tcp*` prints it: the IP's 32-bit words in hex,
/// each in the host's byte order, then `:` and the port in hex.
#[cfg(target_os = "linux")]
fn proc_net_address(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let words = (0..ip.len() / 8)
        .map(|i| u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16).ok())
        .collect::<Option<Vec<u32>>>()?;
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_ne_bytes()).collect();
    let ip = match (
        ip.len(),
        <[u8; 4]>::try_from(bytes.as_slice()),
        <[u8; 16]>::try_from(bytes.as_slice()),
    ) {
        (8, Ok(v4), _) => IpAddr::V4(Ipv4Addr::from(v4)),
        (32, _, Ok(v6)) => IpAddr::V6(Ipv6Addr::from(v6)).to_canonical(),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Under `socks5` the canary (TCP, QUIC and an HTTP provider in the
/// router's records) and the IPNS redirect's own canary see nothing; every
/// connection the router accepted came through the proxy, no datagram
/// reached it, and the proxy was asked for nothing else. The control,
/// `direct` over the same topology in the same process, reaches both
/// canaries and never the proxy.
#[test]
fn under_socks5_the_canary_sees_nothing_and_the_proxy_everything() {
    let canary = Canary::start();
    let redirect = Canary::start();
    let router = Router::start(
        &[
            (
                PEER,
                vec![
                    format!("/ip4/127.0.0.1/tcp/{}", canary.tcp.port()),
                    format!("/ip4/127.0.0.1/udp/{}/quic-v1", canary.udp.port()),
                ],
            ),
            (
                OTHER_PEER,
                vec![format!("/ip4/127.0.0.1/tcp/{}/http", canary.tcp.port())],
            ),
        ],
        Some(redirect.tcp),
    );
    let proxy = Proxy::start();
    proxy
        .fixture
        .forward(Destination::Ip(router.addr), router.addr);
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();

    let started = ipfsd.start(instance("e-1", &router, proxy.network()));
    assert_eq!(started["result"]["instance"], "e-1", "{started}");
    for path in [format!("/ipns/{PEER}"), format!("/ipfs/{ABSENT}")] {
        let status = status(&mut ipfsd, "e-1", &path);
        assert!(matches!(status, 502 | 504), "{path}: {status}");
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(canary.seen(), (0, 0), "the canary was reached");
    assert_eq!(redirect.seen().0, 0, "the redirect was followed");
    let paths = router.paths();
    assert!(
        paths
            .iter()
            .any(|path| path.starts_with("/routing/v1/providers/"))
            && paths
                .iter()
                .any(|path| path.starts_with("/routing/v1/ipns/")),
        "{paths:?}"
    );
    let connects = proxy.connects();
    assert!(
        connects
            .iter()
            .all(|destination| *destination == Destination::Ip(router.addr)),
        "{connects:?}"
    );
    assert_eq!(router.accepted(), connects.len(), "{connects:?}");
    assert_eq!(router.datagrams(), 0, "a datagram to the router");
    assert_eq!(ipfsd.stop("e-1")["result"], json!({ "instance": "e-1" }));

    // The control: `direct`, the same topology, other names.
    let started = ipfsd.start(instance("e-2", &router, json!({ "mode": "direct" })));
    assert_eq!(started["result"]["instance"], "e-2", "{started}");
    let proxied = proxy.fixture.connections();
    // The canary holds what reaches it open, so these may end at their
    // deadline: only what reached the canaries counts.
    for path in [
        format!("/ipns/{OTHER_PEER}"),
        format!("/ipfs/{OTHER_ABSENT}"),
    ] {
        let mut params = get("e-2", &path);
        params["headers_ms"] = json!(5000);
        let id = ipfsd.request("ipfs.request", params);
        ipfsd.reply(id);
    }
    assert!(
        wait_for(Duration::from_secs(5), || {
            let (tcp, udp) = canary.seen();
            tcp > 0 && udp > 0 && redirect.seen().0 > 0
        }),
        "the control: canary {:?}, redirect {:?}",
        canary.seen(),
        redirect.seen()
    );
    assert_eq!(
        proxy.fixture.connections(),
        proxied,
        "the control used the proxy"
    );
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

/// A stop under `socks5`: a request is held at a provider that never
/// answers, reached through the proxy. Once the stop is acknowledged, the
/// request is settled `stopped`, the process holds no socket to the proxy
/// (Linux), and no connection reaches the proxy or the provider.
#[test]
fn a_stop_leaves_no_connection_after_its_acknowledgement() {
    let provider = Canary::holding();
    let public: SocketAddr = "8.8.8.8:80".parse().unwrap();
    let router = Router::start(
        &[(PEER, vec!["/ip4/8.8.8.8/tcp/80/http".to_string()])],
        None,
    );
    let proxy = Proxy::start();
    proxy
        .fixture
        .forward(Destination::Ip(router.addr), router.addr);
    proxy.fixture.forward(Destination::Ip(public), provider.tcp);
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();
    let started = ipfsd.start(instance("e-1", &router, proxy.network()));
    assert_eq!(started["result"]["instance"], "e-1", "{started}");
    let held = ipfsd.request("ipfs.request", get("e-1", &format!("/ipfs/{ABSENT}")));
    assert!(
        wait_for(Duration::from_secs(20), || provider.seen().0 > 0),
        "the provider was never reached through the proxy"
    );
    // The control for the check after the stop: the held request's
    // connection to the proxy is seen.
    #[cfg(target_os = "linux")]
    assert!(
        connections_held_to(proxy.fixture.addr()).expect("the namespace's socket tables") > 0,
        "the held request's connection to the proxy wasn't seen"
    );
    let stop = ipfsd.request("ipfs.stop", json!({ "instance": "e-1" }));
    let reply = ipfsd.reply(held);
    assert_eq!(reply["error"]["code"], "stopped", "{reply}");
    let stopped = ipfsd.reply(stop);
    assert_eq!(stopped["result"], json!({ "instance": "e-1" }), "{stopped}");
    let (proxied, reached) = (proxy.fixture.connections(), provider.seen().0);
    // The kernel's view, where it gives one (Linux's /proc): no socket
    // holds a connection to the proxy any more.
    #[cfg(target_os = "linux")]
    assert_eq!(
        connections_held_to(proxy.fixture.addr()).expect("the namespace's socket tables"),
        0,
        "a connection to the proxy outlived the stop"
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        proxy.fixture.connections(),
        proxied,
        "a connection after the stop"
    );
    assert_eq!(provider.seen().0, reached);
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

/// Two instances in sequence, under different policies: the `socks5` one's
/// router is reached through the proxy, the `direct` one's directly, and
/// the proxy sees nothing of the second.
#[test]
fn instances_in_sequence_keep_their_own_policies() {
    let router = Router::start(&[(PEER, Vec::new())], None);
    let proxy = Proxy::start();
    proxy
        .fixture
        .forward(Destination::Ip(router.addr), router.addr);
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();

    let started = ipfsd.start(instance("e-1", &router, proxy.network()));
    assert_eq!(started["result"]["instance"], "e-1", "{started}");
    status(&mut ipfsd, "e-1", &format!("/ipfs/{ABSENT}"));
    let through = proxy.connects().len();
    assert!(
        through > 0,
        "the socks5 instance's router wasn't reached through the proxy"
    );
    assert_eq!(router.accepted(), through);
    assert_eq!(ipfsd.stop("e-1")["result"], json!({ "instance": "e-1" }));

    let started = ipfsd.start(instance("e-2", &router, json!({ "mode": "direct" })));
    assert_eq!(started["result"]["instance"], "e-2", "{started}");
    status(&mut ipfsd, "e-2", &format!("/ipfs/{OTHER_ABSENT}"));
    assert!(
        router.accepted() > through,
        "the direct instance's router wasn't reached"
    );
    assert_eq!(
        proxy.connects().len(),
        through,
        "the direct instance used the proxy"
    );
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

/// An unreachable proxy: the instance starts, since nothing is sent at
/// start, and its requests fail 502 or 504; nothing falls back to a direct
/// connection, so the router sees nothing.
#[test]
fn an_unreachable_proxy_fails_requests_and_never_falls_back() {
    let router = Router::start(&[(PEER, Vec::new())], None);
    // A port nothing listens on.
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();
    let started = ipfsd.start(instance(
        "e-1",
        &router,
        json!({ "mode": "socks5", "ip": "127.0.0.1", "port": closed.port() }),
    ));
    assert_eq!(started["result"]["instance"], "e-1", "{started}");
    let status = status(&mut ipfsd, "e-1", &format!("/ipfs/{ABSENT}"));
    assert!(matches!(status, 502 | 504), "{status}");
    assert_eq!(router.accepted(), 0, "a direct connection to the router");
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}
