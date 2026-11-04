#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::str::FromStr as _;

use super::*;

const PORT: u16 = 8776;
const NID: &str = "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

fn connect(text: &str) -> ConnectAddress {
    let nid = radicle::prelude::NodeId::from_str(NID).unwrap();
    ConnectAddress::from((nid, address(text)))
}

fn address(text: &str) -> Address {
    Address::from_str(text).unwrap()
}

/// A gate with fixed answers, `configured` as its seeds, under `nat64`.
fn gate(configured: &[&str], answers: &[(&str, &[IpAddr])], nat64: Nat64State) -> DialGate {
    let configured: Vec<_> = configured.iter().map(|text| connect(text)).collect();
    DialGate {
        resolver: Resolver::Fixed(
            answers
                .iter()
                .map(|(name, ips)| ((*name).to_owned(), ips.to_vec()))
                .collect::<HashMap<_, _>>(),
        ),
        configured: configured_targets(&configured),
        nat64: Nat64::fixed(nat64),
    }
}

/// Whether the untrusted IP literal target `ip` passes.
fn passes(gate: &DialGate, ip: &str) -> bool {
    let ip = IpAddr::from_str(ip).unwrap();
    let target = SocketAddr::new(ip, PORT);
    gate.allows(&Address::from(target), &target)
}

#[test]
fn untrusted_ipv4_passes_only_at_a_global_unicast_address() {
    let gate = gate(&[], &[], Nat64State::NONE);
    for refused in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.5",
        "100.64.0.1",
        "169.254.1.1",
        "192.0.2.10",
        "198.51.100.7",
        "203.0.113.9",
        "224.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
    ] {
        assert!(!passes(&gate, refused), "{refused}");
    }
    for global in ["1.1.1.1", "8.8.8.8", "185.199.108.153"] {
        assert!(passes(&gate, global), "{global}");
    }
}

#[test]
fn ipv6_forms_that_embed_a_refused_ipv4_are_refused() {
    let gate = gate(&[], &[], Nat64State::NONE);
    for refused in [
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        // IPv4-mapped, judged as the address it maps.
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        // NAT64's well-known prefix, embedding a private address.
        "64:ff9b::a00:1",
        // 6to4, embedding 10.0.0.1.
        "2002:a00:1::",
    ] {
        assert!(!passes(&gate, refused), "{refused}");
    }
    for global in ["::ffff:8.8.8.8", "2606:4700:4700::1111"] {
        assert!(passes(&gate, global), "{global}");
    }
}

#[test]
fn ipv6_outside_the_fixed_forms_waits_for_nat64_discovery() {
    let pending = gate(&[], &[], Nat64State::Pending);
    assert!(!passes(&pending, "2606:4700:4700::1111"));
    // An IPv4-mapped address is judged as its IPv4 address meanwhile.
    assert!(passes(&pending, "::ffff:8.8.8.8"));
    assert!(passes(&pending, "8.8.8.8"));
}

#[test]
fn configured_targets_are_exempt_by_exact_host_and_port() {
    let lan: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
    let gate = gate(
        &["192.168.1.5:8776", "seed.lan:8776"],
        &[],
        Nat64State::NONE,
    );
    // An address seed, at its port only.
    let seed = SocketAddr::from(([192, 168, 1, 5], PORT));
    assert!(gate.allows(&Address::from(seed), &seed));
    let other_port = SocketAddr::from(([192, 168, 1, 5], 8777));
    assert!(!gate.allows(&Address::from(other_port), &other_port));
    // A named seed, whatever it resolves to, at its port.
    let resolved = SocketAddr::new(lan, PORT);
    assert!(gate.allows(&address("seed.lan:8776"), &resolved));
    assert!(gate.allows(&address("SEED.LAN.:8776"), &resolved));
    assert!(!gate.allows(&address("seed.lan:8777"), &SocketAddr::new(lan, 8777)));
    // Another name that resolves to the same address isn't configured.
    assert!(!gate.allows(&address("other.lan:8776"), &resolved));
    // Nor is an untrusted peer at the configured name's address.
    assert!(!gate.allows(&Address::from(resolved), &resolved));
}

#[test]
fn names_resolve_once_and_their_answers_are_judged() {
    let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
    let global: IpAddr = Ipv4Addr::new(1, 1, 1, 1).into();
    let gate = gate(
        &[],
        &[
            ("loopback.example", &[loopback]),
            ("mixed.example", &[loopback, global]),
        ],
        Nat64State::NONE,
    );
    // A name that resolves to loopback: its answer is refused.
    let answer = gate.resolve("loopback.example", PORT).unwrap();
    assert_eq!(answer, [SocketAddr::new(loopback, PORT)]);
    assert!(!gate.allows(&address("loopback.example:8776"), &answer[0]));
    // Each answer is judged on its own: heartwood connects to one that
    // passes.
    let answer = gate.resolve("Mixed.Example.", PORT).unwrap();
    let allowed: Vec<_> = answer
        .iter()
        .filter(|addr| gate.allows(&address("mixed.example:8776"), addr))
        .collect();
    assert_eq!(allowed, [&SocketAddr::new(global, PORT)]);
    // An empty answer fails the dial.
    let empty = gate.resolve("nowhere.example", PORT).unwrap_err();
    assert_eq!(empty.kind(), io::ErrorKind::NotFound);
    // An IP literal is its own answer.
    assert_eq!(
        gate.resolve("8.8.8.8", PORT).unwrap(),
        [SocketAddr::from(([8, 8, 8, 8], PORT))]
    );
}

#[test]
fn onion_names_are_never_resolved() {
    let gate = gate(&[], &[], Nat64State::NONE);
    let onion = "xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion";
    for host in [onion.to_owned(), onion.to_uppercase(), format!("{onion}.")] {
        let refused = gate.resolve(&host, PORT).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{host}");
    }
    assert!(gate.resolve("not a host", PORT).is_err());
    assert!(!gate.proxy_resolves_names());
}

#[test]
fn direct_routing_drops_onions_and_has_no_proxy() {
    let routing = routing(&NetworkPolicy::Direct, &[], Nat64::pending()).unwrap();
    assert_eq!(routing.proxy, None);
    assert_eq!(routing.onion, AddressConfig::Drop);
    assert!(!routing.gate.proxy_resolves_names());
}

/// A SOCKS5 proxy that takes one connection: username/password, then a
/// `RESOLVE`, answered with `answer` (`None`: host unreachable). It returns
/// the method list offered, the username, and the name asked for.
fn resolving_proxy(
    answer: Option<Ipv4Addr>,
) -> (
    SocketAddr,
    std::thread::JoinHandle<(Vec<u8>, String, String)>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let byte = |stream: &mut std::net::TcpStream| {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).unwrap();
            b[0]
        };
        assert_eq!(byte(&mut stream), 5);
        let methods: Vec<u8> = (0..byte(&mut stream)).map(|_| byte(&mut stream)).collect();
        stream.write_all(&[5, 2]).unwrap();
        assert_eq!(byte(&mut stream), 1);
        let user: Vec<u8> = (0..byte(&mut stream)).map(|_| byte(&mut stream)).collect();
        let _password: Vec<u8> = (0..byte(&mut stream)).map(|_| byte(&mut stream)).collect();
        stream.write_all(&[1, 0]).unwrap();
        let head: Vec<u8> = (0..4).map(|_| byte(&mut stream)).collect();
        assert_eq!(head, [5, 0xF0, 0, 3], "a RESOLVE of a name");
        let name: Vec<u8> = (0..byte(&mut stream)).map(|_| byte(&mut stream)).collect();
        let _port = [byte(&mut stream), byte(&mut stream)];
        match answer {
            Some(ip) => {
                let mut reply = vec![5, 0, 0, 1];
                reply.extend(ip.octets());
                reply.extend([0, 0]);
                stream.write_all(&reply).unwrap();
            }
            None => stream.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap(),
        }
        (
            methods,
            String::from_utf8(user).unwrap(),
            String::from_utf8(name).unwrap(),
        )
    });
    (addr, served)
}

#[test]
fn socks5_resolves_names_through_the_proxy_and_judges_its_answer() {
    let (proxy, served) = resolving_proxy(Some(Ipv4Addr::LOCALHOST));
    let routing = routing(
        &NetworkPolicy::Socks5 { proxy },
        &[],
        Nat64::fixed(Nat64State::NONE),
    )
    .unwrap();
    assert_eq!(routing.proxy, Some(proxy));
    assert_eq!(routing.onion, AddressConfig::Proxy { address: proxy });
    let answer = routing.gate.resolve("seed.example", PORT).unwrap();
    assert_eq!(answer, [SocketAddr::from(([127, 0, 0, 1], PORT))]);
    // The proxy's answer is judged like any other: loopback is refused.
    assert!(
        !routing
            .gate
            .allows(&address("seed.example:8776"), &answer[0])
    );
    let (methods, user, name) = served.join().unwrap();
    // Username/password alone: a proxy that won't take it fails the lookup.
    assert_eq!(methods, [2]);
    assert_eq!(user, Credentials::USERNAME);
    assert_eq!(name, "seed.example");
}

#[test]
fn socks5_a_failed_lookup_fails_the_dial() {
    let (proxy, served) = resolving_proxy(None);
    let routing = routing(
        &NetworkPolicy::Socks5 { proxy },
        &[],
        Nat64::fixed(Nat64State::NONE),
    )
    .unwrap();
    assert!(routing.gate.resolve("seed.example", PORT).is_err());
    served.join().unwrap();
}

#[test]
fn the_gate_prints_no_target_or_credential() {
    let gate = gate(&["seed.lan:8776"], &[], Nat64State::NONE);
    assert_eq!(format!("{gate:?}"), "DialGate { .. }");
}

/// A loopback listener standing in for Arti, which only notes whether a
/// connection was made to it.
struct Recorder(TcpListener);

impl Recorder {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self(listener)
    }

    fn addr(&self) -> SocketAddr {
        self.0.local_addr().unwrap()
    }

    /// Whether a connection was made to it, waiting up to `within` for one.
    fn dialled(&self, within: Duration) -> bool {
        let until = Instant::now() + within;
        loop {
            match self.0.accept() {
                Ok(_) => return true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= until {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("{e}"),
            }
        }
    }
}

/// The node ID of the key with `seed`, repeated, as its seed.
fn node_id(seed: u8) -> radicle::prelude::NodeId {
    use radicle::crypto::Signer as _;

    *radicle::crypto::SigningKey::from_seed(radicle::crypto::Seed::new([seed; 32])).public_key()
}

/// A Radicle home for a test node, on the test network, with no seeds:
/// short enough for its control socket's path.
fn node_home() -> tempfile::TempDir {
    let mut home = tempfile::Builder::new().prefix("dial").tempdir().unwrap();
    if cfg!(unix) && home.path().join("node/control.sock").as_os_str().len() > 100 {
        home = tempfile::Builder::new()
            .prefix("dial")
            .tempdir_in("/tmp")
            .unwrap();
    }
    std::fs::write(
        home.path().join("config.json"),
        r#"{"preferredSeeds":[],"node":{"alias":"dial","network":"test"}}"#,
    )
    .unwrap();
    home
}

#[test]
// Review of #245, round 1: `socks5` routing gives the node a global proxy
// and an onion route, both Arti, and heartwood reaches either without asking
// the gate. An isolated node opens no socket (0008, R-12 part 3), so with
// this routing an explicit connect to an onion or a named peer, asked
// through the control socket, never reaches the proxy. libradicle#26 drops
// both routes under `isolated`; libradicle before it (5448fd8) reached the
// proxy here.
fn socks5_routing_on_an_isolated_node_reaches_no_proxy() {
    use radicle::node::Handle as _;

    let proxy = Recorder::new();
    let routing = routing(
        &NetworkPolicy::Socks5 {
            proxy: proxy.addr(),
        },
        &[],
        Nat64::fixed(Nat64State::NONE),
    )
    .unwrap();
    assert_eq!(routing.proxy, Some(proxy.addr()));
    assert_eq!(
        routing.onion,
        AddressConfig::Proxy {
            address: proxy.addr()
        }
    );

    let home = node_home();
    let mut seed = [12u8; 32];
    let node = libradicle::Embedded::start_with_key(
        libradicle::Options {
            home: home.path().to_path_buf(),
            alias: "dial".into(),
            listen: vec![],
            control_socket: true,
            routing: Some(routing),
            isolated: true,
        },
        libradicle::HostKey::from_bytes(&mut seed).unwrap(),
    )
    .unwrap();
    let control = || radicle::node::Node::new(home.path().join("node").join("control.sock"));

    let onion = "xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion:8776";
    for (target, peer) in [(onion, 4), ("seed.example:8776", 5)] {
        // Whatever the answer, short of `Connected`: what matters is whether
        // a socket reached the proxy. Each target is a peer of its own, so
        // that one attempt's session doesn't answer for the next.
        let result = control().connect(
            node_id(peer),
            address(target),
            radicle::node::ConnectOptions {
                persistent: false,
                timeout: Duration::from_secs(2),
            },
        );
        assert!(
            !proxy.dialled(Duration::from_millis(500)),
            "{target}: an isolated node reached its proxy ({result:?})"
        );
        assert!(
            !matches!(result, Ok(radicle::node::ConnectResult::Connected)),
            "{target}: {result:?}"
        );
    }
    // The running configuration has neither route.
    let config = control().config().unwrap();
    assert_eq!(config.proxy, None);
    assert_eq!(config.onion, AddressConfig::Drop);

    node.shutdown().unwrap();
}
