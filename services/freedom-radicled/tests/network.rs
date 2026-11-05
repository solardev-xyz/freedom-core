//! The node's network through the real binary (design 0008, "Network
//! policy", "Modes", "The address policy" and "Tests first": "Network"):
//! a local peer, a SOCKS5 fixture with `RESOLVE`, onion names, `config.json`
//! routes that change nothing, and untrusted addresses the policy refuses.
//!
//! Everything here is on loopback: the peers are libradicle nodes in this
//! test process behind the hermetic gate, the proxy and the canaries are
//! listeners of its own, and the service's own gate is held to loopback by
//! the test hooks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::fixture::{self, OTHER_SEED};
use common::*;
use radicle::node::address::Store as _;
use serde_json::json;

/// An onion v3 name: no route reaches it here.
const ONION: &str = "xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion";

/// Waits up to `within` for `done`.
fn eventually(within: Duration, done: impl Fn() -> bool) -> bool {
    let until = Instant::now() + within;
    while !done() {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// A loopback port nothing listens on, a moment ago.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The node ID of `byte`'s key, repeated, as its seed.
fn nid(byte: u8) -> String {
    fixture::nid_of(&[byte; 32])
}

/// A listener that only notes whether anything connected to it.
struct Canary(TcpListener);

impl Canary {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self(listener)
    }

    fn addr(&self) -> SocketAddr {
        self.0.local_addr().unwrap()
    }

    fn touched(&self) -> bool {
        match self.0.accept() {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => panic!("{e}"),
        }
    }
}

/// A Radicle peer on loopback, as `OTHER_SEED`'s identity, in this process,
/// behind the hermetic gate: it takes connections and dials no one.
struct Peer {
    node: Option<libradicle::Embedded>,
    addr: SocketAddr,
    _home: tempfile::TempDir,
}

impl Peer {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        configure(home.path(), json!({ "alias": "peer" }));
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        let mut seed = OTHER_SEED;
        let node = libradicle::Embedded::start_with_key(
            libradicle::Options {
                home: home.path().to_path_buf(),
                alias: "peer".into(),
                listen: vec![addr],
                control_socket: false,
                routing: Some(libradicle::Routing {
                    proxy: None,
                    onion: radicle::node::config::AddressConfig::Drop,
                    gate: common::hermetic::gate(),
                }),
                seeding_policy: None,
                isolated: false,
                repositories: None,
            },
            libradicle::HostKey::from_bytes(&mut seed).unwrap(),
        )
        .unwrap();
        Self {
            node: Some(node),
            addr,
            _home: home,
        }
    }

    fn nid(&self) -> String {
        fixture::nid_of(&OTHER_SEED)
    }

    fn connected(&self) -> usize {
        self.node.as_ref().unwrap().connected_peers().unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            let _ = node.shutdown();
        }
    }
}

/// `config.json`'s routes, conflicting with the service's: a global proxy
/// and an onion proxy, each a canary. Neither may see a connection: the
/// service sets every routing field in memory.
fn conflicting_routes(proxy: &Canary, onion: &Canary) -> serde_json::Value {
    json!({
        "proxy": proxy.addr().to_string(),
        "onion": { "mode": "proxy", "address": onion.addr().to_string() },
    })
}

#[test]
fn direct_mode_dials_a_configured_local_peer_and_config_json_routes_change_nothing() {
    let peer = Peer::new();
    let (proxy, onion) = (Canary::new(), Canary::new());
    let dirs = Dirs::new();
    let mut node = conflicting_routes(&proxy, &onion);
    node["connect"] = json!([
        format!("{}@{}", peer.nid(), peer.addr),
        format!("{}@{ONION}:8776", nid(4)),
    ]);
    configure(&dirs.home, node);

    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    // The configured loopback peer is exempt from the address policy, by
    // its exact address, and the node reaches it directly.
    assert!(
        eventually(Duration::from_secs(30), || peer.connected() > 0),
        "the node never reached its configured peer"
    );
    // A moment more for the onion peer's dial, which `direct` mode drops.
    std::thread::sleep(Duration::from_secs(2));
    assert!(!proxy.touched(), "config.json's proxy was used");
    assert!(!onion.touched(), "config.json's onion route was used");
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// What the SOCKS5 fixture was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Asked {
    /// `CONNECT` (1) or `RESOLVE` (0xF0).
    command: u8,
    /// The host: an IP literal, or a name for an address of type 3.
    host: String,
    by_name: bool,
    port: u16,
    /// The RFC 1929 username.
    user: String,
}

/// A SOCKS5 proxy on loopback with Tor's `RESOLVE`, as Arti answers it:
/// `peer.test` resolves to loopback, any other name fails. A `CONNECT` to
/// an IP literal is relayed to it; one to a name is refused. Every request
/// is recorded, and only username/password authentication is taken.
struct Socks {
    addr: SocketAddr,
    asked: Arc<Mutex<Vec<Asked>>>,
}

impl Socks {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let record = asked.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let record = record.clone();
                std::thread::spawn(move || {
                    let _ = serve(stream, &record);
                });
            }
        });
        Self { addr, asked }
    }

    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }
}

fn byte(stream: &mut TcpStream) -> io::Result<u8> {
    let mut b = [0u8; 1];
    stream.read_exact(&mut b)?;
    Ok(b[0])
}

fn bytes(stream: &mut TcpStream, n: usize) -> io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    stream.read_exact(&mut b)?;
    Ok(b)
}

fn serve(mut stream: TcpStream, record: &Mutex<Vec<Asked>>) -> io::Result<()> {
    assert_eq!(byte(&mut stream)?, 5);
    let n = byte(&mut stream)? as usize;
    let methods = bytes(&mut stream, n)?;
    if !methods.contains(&2) {
        return stream.write_all(&[5, 0xFF]);
    }
    stream.write_all(&[5, 2])?;
    assert_eq!(byte(&mut stream)?, 1);
    let n = byte(&mut stream)? as usize;
    let user = String::from_utf8(bytes(&mut stream, n)?).unwrap();
    let n = byte(&mut stream)? as usize;
    let _password = bytes(&mut stream, n)?;
    stream.write_all(&[1, 0])?;
    let head = bytes(&mut stream, 4)?;
    let (command, atyp) = (head[1], head[3]);
    let (host, by_name) = match atyp {
        1 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(bytes(&mut stream, 4)?).unwrap()).to_string(),
            false,
        ),
        3 => {
            let n = byte(&mut stream)? as usize;
            (String::from_utf8(bytes(&mut stream, n)?).unwrap(), true)
        }
        4 => (
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes(&mut stream, 16)?).unwrap())
                .to_string(),
            false,
        ),
        _ => return Ok(()),
    };
    let port = u16::from_be_bytes(<[u8; 2]>::try_from(bytes(&mut stream, 2)?).unwrap());
    record.lock().unwrap().push(Asked {
        command,
        host: host.clone(),
        by_name,
        port,
        user,
    });
    let refused = [5, 4, 0, 1, 0, 0, 0, 0, 0, 0];
    match (command, by_name) {
        (0xF0, true) if host == "peer.test" => stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]),
        (1, false) => {
            let Ok(upstream) = TcpStream::connect((host.as_str(), port)) else {
                return stream.write_all(&refused);
            };
            stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
            let (mut a, mut b) = (stream.try_clone()?, upstream.try_clone()?);
            let (mut c, mut d) = (upstream, stream);
            std::thread::spawn(move || io::copy(&mut a, &mut b));
            io::copy(&mut c, &mut d).map(drop)
        }
        _ => stream.write_all(&refused),
    }
}

/// `socks5` mode (0008, "Modes"): names resolve through the proxy's
/// `RESOLVE`, and the dial is a `CONNECT` to the checked address; a name
/// that doesn't resolve fails its dial, and no `CONNECT` carries it. Only
/// onion names go to the proxy as names. Every request is authenticated.
#[test]
fn socks5_mode_resolves_through_the_proxy_and_connects_to_checked_addresses() {
    let peer = Peer::new();
    let socks = Socks::new();
    let (proxy, onion) = (Canary::new(), Canary::new());
    let dirs = Dirs::new();
    let mut node = conflicting_routes(&proxy, &onion);
    node["connect"] = json!([
        format!("{}@peer.test:{}", peer.nid(), peer.addr.port()),
        format!("{}@nowhere.test:8776", nid(5)),
        format!("{}@{ONION}:8776", nid(4)),
    ]);
    configure(&dirs.home, node);

    let mut radicled = Radicled::serve_on(&dirs, &format!("socks5:{}", socks.addr), &[]);
    assert!(radicled.start()["result"].is_object());
    assert!(
        eventually(Duration::from_secs(30), || peer.connected() > 0),
        "the node never reached its peer through the proxy: {:?}",
        socks.asked()
    );
    assert!(
        eventually(Duration::from_secs(10), || {
            let asked = socks.asked();
            asked.iter().any(|a| a.host == "nowhere.test") && asked.iter().any(|a| a.host == ONION)
        }),
        "{:?}",
        socks.asked()
    );
    let asked = socks.asked();
    let resolved = |name: &str| asked.iter().any(|a| a.command == 0xF0 && a.host == name);
    assert!(
        resolved("peer.test") && resolved("nowhere.test"),
        "{asked:?}"
    );
    assert!(
        asked.iter().any(|a| a.command == 1
            && !a.by_name
            && a.host == "127.0.0.1"
            && a.port == peer.addr.port()),
        "no CONNECT to the checked address: {asked:?}"
    );
    // A name goes to the proxy only to be resolved, or as an onion name.
    for a in asked.iter().filter(|a| a.command == 1 && a.by_name) {
        assert_eq!(a.host, ONION, "a CONNECT carried a name: {asked:?}");
    }
    // Every request was authenticated: the gate's lookups and each peer's
    // streams with credentials of their own.
    assert!(asked.iter().all(|a| !a.user.is_empty()), "{asked:?}");
    assert!(
        !proxy.touched() && !onion.touched(),
        "config.json's routes were used"
    );
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// Puts each of `addrs` in `home`'s address book, each a peer of its own
/// learned from another peer: untrusted targets (0008, "The address
/// policy").
fn learned(home: &Path, addrs: &[SocketAddr]) {
    std::fs::create_dir_all(home.join("node")).unwrap();
    let mut book = radicle::profile::Home::new(home.to_path_buf())
        .unwrap()
        .addresses(Default::default())
        .unwrap();
    for (i, addr) in addrs.iter().enumerate() {
        let id: radicle::prelude::NodeId = nid(100 + i as u8).parse().unwrap();
        book.insert(
            &id,
            radicle::node::PROTOCOL_VERSION,
            radicle::node::Features::SEED,
            &radicle::node::Alias::new("learned"),
            0,
            &radicle::node::UserAgent::from_str("/test/").unwrap(),
            radicle::profile::env::local_time().into(),
            [radicle::node::KnownAddress::new(
                radicle::node::Address::from(*addr),
                radicle::node::address::Source::Peer,
            )],
        )
        .unwrap();
    }
}

/// Addresses learned from peers that the policy refuses are never dialled:
/// loopback, private, and the IPv6 forms that embed them (0007's embedded
/// IPv4 cases). A node with a gate that admits loopback dials the same
/// address book at once, so the absence isn't for want of trying.
#[test]
fn untrusted_addresses_the_policy_refuses_are_never_dialled() {
    let canary = Canary::new();
    let port = canary.addr().port();
    let refused: Vec<SocketAddr> = [
        format!("127.0.0.1:{port}"),
        format!("[::ffff:127.0.0.1]:{port}"),
        format!("[64:ff9b::7f00:1]:{port}"),
        format!("[2002:7f00:1::1]:{port}"),
        format!("10.0.0.1:{port}"),
        format!("[::ffff:192.168.1.2]:{port}"),
    ]
    .iter()
    .map(|a| a.parse().unwrap())
    .collect();

    // The control: libradicle's node, whose hermetic gate admits loopback,
    // dials the loopback entry as it starts.
    let control = Canary::new();
    let home = tempfile::tempdir().unwrap();
    configure(home.path(), json!({ "peers": { "type": "dynamic" } }));
    learned(home.path(), &[control.addr()]);
    fixture::with_node_dialing(home.path(), &OTHER_SEED, || {
        assert!(
            eventually(Duration::from_secs(30), || control.touched()),
            "the control node never dialled its address book"
        );
    });

    let dirs = Dirs::new();
    configure(&dirs.home, json!({ "peers": { "type": "dynamic" } }));
    learned(&dirs.home, &refused);
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    std::thread::sleep(Duration::from_secs(5));
    assert!(
        !canary.touched(),
        "an untrusted loopback address was dialled"
    );
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}
