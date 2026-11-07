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
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::quarantine;
use serde_json::json;

/// An onion v3 name: no route reaches it here.
const ONION: &str = "xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion";

/// Waits up to `within` for `done`.
fn eventually(within: Duration, mut done: impl FnMut() -> bool) -> bool {
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
        Self::with_seeds(&[])
    }

    /// A peer whose `config.json` names `seeds` as its preferred seeds:
    /// libradicle's clone then asks one it is connected to even when no
    /// inventory names it.
    fn with_seeds(seeds: &[String]) -> Self {
        let home = tempfile::tempdir().unwrap();
        configure(home.path(), json!({ "alias": "peer" }));
        preferred(home.path(), seeds);
        Self::start(home)
    }

    /// A peer that holds and seeds a repository of its own, `name`, made in
    /// its home before it starts.
    fn serving(name: &str) -> (Self, RepoId) {
        let home = tempfile::tempdir().unwrap();
        configure(home.path(), json!({ "alias": "peer" }));
        let rid = fixture::repository(home.path(), &OTHER_SEED, name);
        (Self::start(home), rid)
    }

    /// Starts the peer on its home, listening on loopback.
    fn start(home: tempfile::TempDir) -> Self {
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

    /// How many nodes the peer's routing table says seed `rid`: those whose
    /// inventory, as they announced it, holds it.
    fn seeders(&mut self, rid: RepoId) -> usize {
        self.node.as_mut().unwrap().seeders(rid).unwrap()
    }

    /// Seeds `rid` and fetches it from a node that seeds it, or from a
    /// connected preferred seed.
    fn clone_repo(&mut self, rid: RepoId) -> Result<(), libradicle::Error> {
        self.node
            .as_mut()
            .unwrap()
            .clone_repo(rid, Duration::from_secs(30))
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            let _ = node.shutdown();
        }
    }
}

/// Sets `home`'s `config.json` preferred seeds to `seeds`.
fn preferred(home: &Path, seeds: &[String]) {
    let config = home.join("config.json");
    let mut fields: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    fields["preferredSeeds"] = json!(seeds);
    std::fs::write(&config, fields.to_string()).unwrap();
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

/// A repository the quarantine record holds for a namespace stays closed on
/// the running node: `rad.start` hands the node the repository gate it
/// closed (0008, "The repository gate"). Its inventory, as the peer learns
/// it, leaves the repository out, and a fetch of it from the node is
/// refused, while an open repository beside it is announced and served.
#[test]
fn a_quarantined_repository_is_neither_announced_nor_served() {
    let mut peer = Peer::with_seeds(&[format!("{NID}@127.0.0.1:{}", free_port())]);
    let dirs = Dirs::new();
    configure(
        &dirs.home,
        json!({ "connect": [format!("{}@{}", peer.nid(), peer.addr)] }),
    );
    // Made by a third identity, seeded by the node: imported, each is
    // seeded explicitly.
    let creator = [9; 32];
    let open = fixture::repository(&dirs.home, &creator, "open");
    let closed = fixture::repository(&dirs.home, &creator, "closed");
    fixture::quarantine(&dirs.home, closed, quarantine::Kind::Namespace);

    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    // The node's inventory has reached the peer: the open repository is in
    // it, the quarantined one isn't.
    assert!(
        eventually(Duration::from_secs(30), || peer.seeders(open) > 0),
        "the peer never learned the node's inventory"
    );
    assert_eq!(
        peer.seeders(closed),
        0,
        "the quarantined repository was announced"
    );
    // The node serves the open repository, and refuses the quarantined one:
    // the peer asks it, its connected preferred seed, all the same.
    peer.clone_repo(open).unwrap();
    match peer.clone_repo(closed) {
        Err(libradicle::Error::FetchFailed(rid, _)) => assert_eq!(rid, closed),
        other => panic!("the quarantined repository's fetch: {other:?}"),
    }
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// 0008, "Methods": `rad.connect_seeds` dials the seed book through the
/// node, whose dials go through the service's gate, and answers today's
/// report: the text libradicle's `json::seed_report` writes for it, byte
/// for byte, as main reads it from the add-on (vectors/radicle-network.json
/// pins the shapes). On the test network the book is the two preferred
/// seeds: a loopback peer, and a port nothing listens on, whose failure the
/// report names.
#[test]
fn connect_seeds_answers_libradicles_report_of_its_dials() {
    let peer = Peer::new();
    let refused = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    preferred(
        &dirs.home,
        &[
            format!("{}@{}", peer.nid(), peer.addr),
            format!("{}@{refused}", nid(5)),
        ],
    );
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    let sent = Instant::now();
    let reply = radicled.call("rad.connect_seeds", json!({ "timeout_ms": 10_000 }));
    let report = &reply["result"];
    assert!(sent.elapsed() < Duration::from_secs(10 + 30), "{reply}");
    let number = |key: &str| usize::try_from(report[key].as_u64().unwrap()).unwrap();
    let rebuilt = libradicle::SeedConnectReport {
        attempted: number("attempted"),
        connected: number("connected"),
        target: number("target"),
        target_reached: report["targetReached"].as_bool().unwrap(),
        elapsed: Duration::from_millis(report["elapsedMs"].as_u64().unwrap()),
        failures: report["failures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| libradicle::SeedConnectFailure {
                nid: f["nid"].as_str().unwrap().into(),
                addr: f["addr"].as_str().unwrap().into(),
                reason: f["reason"].as_str().unwrap().into(),
            })
            .collect(),
    };
    let text = libradicle::json::to_string(|w| libradicle::json::seed_report(w, &rebuilt));
    assert_eq!(serde_json::to_string(report).unwrap(), text);
    // The peer is reached, the closed port isn't: 1 of the 2 the book's
    // size makes the target. The node may have reached the peer itself.
    assert_eq!((number("connected"), number("target")), (1, 2), "{reply}");
    assert_eq!(report["targetReached"], false);
    assert!((1..=2).contains(&number("attempted")), "{reply}");
    let failures = report["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1, "{reply}");
    assert_eq!(failures[0]["nid"], nid(5));
    assert_eq!(failures[0]["addr"], refused.to_string());
    assert!(eventually(Duration::from_secs(10), || peer.connected() > 0));
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// 0008, "Methods" and "Progress": `rad.clone` of a repository a loopback
/// peer seeds: libradicle's own clone, its progress as `rad.progress`
/// events, the terminal `done` last, then `{ ok }`; the
/// repository is then read from storage. Proven, the clone leaves no
/// marker after a clean stop.
#[test]
fn a_clone_from_a_loopback_peer_is_ok_and_its_repository_is_read() {
    let (peer, rid) = Peer::serving("shared");
    let at = format!("{}@{}", peer.nid(), peer.addr);
    let dirs = Dirs::new();
    configure(&dirs.home, json!({ "connect": [at.clone()] }));
    preferred(&dirs.home, &[at]);
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    assert!(
        eventually(Duration::from_secs(30), || peer.connected() > 0),
        "the node never reached its peer"
    );
    let id = radicled.request(
        "rad.clone",
        json!({ "rid": rid.to_string(), "timeout_ms": 30_000, "progress": true }),
    );
    let (events, reply) = radicled.progress(id);
    assert_eq!(reply["result"], json!({ "ok": true }), "{reply}");
    let phases: Vec<String> = events
        .iter()
        .map(|m| {
            let event: serde_json::Value =
                serde_json::from_str(m["data"]["event"].as_str().unwrap()).unwrap();
            event["phase"].as_str().unwrap().to_owned()
        })
        .collect();
    // libradicle's `resolving` and `connecting` may fold into the latest
    // before the writer takes them.
    assert_eq!(
        phases.last().map(String::as_str),
        Some("done"),
        "{phases:?}"
    );
    assert!(phases.iter().any(|p| p == "fetching"), "{phases:?}");
    let info: serde_json::Value = serde_json::from_slice(
        &radicled
            .read("repo_info", json!({ "rid": rid.to_string() }))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(info["rid"], rid.to_string());
    assert_eq!(info["name"], "shared");
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
}
