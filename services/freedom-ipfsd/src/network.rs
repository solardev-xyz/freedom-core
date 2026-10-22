//! The network policy an instance runs under (design 0007, "Network
//! policy", "Modes").
//!
//! `ipfs.start`'s `network` member:
//!
//! ```jsonc
//! "network": { "mode": "direct" }
//! "network": { "mode": "socks5", "ip": "127.0.0.1", "port": 9150 }
//! ```
//!
//! - **`direct`:** the gate's first part (0007, "Modes": "the gate comes to
//!   `direct` in two parts"): every target classified, onions and
//!   non-network multiaddrs refused before any socket, redirects followed by
//!   the policy's own loop, every socket, DNS query and hop asking the
//!   instance's capability, and the environment's proxy variables ignored
//!   (deviation `env-proxy`). The address table comes with NAT64 discovery;
//!   until then names resolve as before (deviation `address-policy` applies
//!   to `socks5` only).
//! - **`socks5`:** every connection through the proxy at `ip` and `port`,
//!   failing closed. Ordinary names are resolved by the proxy (Tor's
//!   `RESOLVE`), every answer passes the gate, and the connection goes to
//!   the checked address; onions take their own route. No credentials are
//!   sent: whether each instance sends its own is 0007's open question 11.
//!
//! The configured targets, exempt from the address policy by exact host and
//! port, are the delegated routers and the DoH endpoint (0007, "The gate").
//! The proxy's own endpoint isn't one: it is the transport (0007 as amended
//! by #158).
//!
//! The policy is parsed here, apart from the rest of `ipfs.start`, so it can
//! move as a unit if it becomes a spawn argument (`--network`) rather than
//! a member of `ipfs.start`: only the caller of [`parse`] would change.

use std::net::{IpAddr, SocketAddr};

use freedom_ipfs_gateway::net::gate::{ConfiguredTargets, Target, parse_url};
use freedom_ipfs_gateway::net::{Addresses, Network};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Direct connections, behind the gate's classification and the
    /// capability: the default.
    Direct,
    /// Every connection through the SOCKS5 proxy at this endpoint.
    Socks5 { proxy: SocketAddr },
}

/// Parses `ipfs.start`'s `network` member. The error is a fixed message for
/// `invalid_argument`, which never quotes the input.
pub fn parse(network: &Value) -> Result<NetworkPolicy, &'static str> {
    let Some(members) = network.as_object() else {
        return Err("network must be an object");
    };
    match members.get("mode").and_then(Value::as_str) {
        Some("direct") if members.len() == 1 => Ok(NetworkPolicy::Direct),
        Some("direct") => Err("network mode direct takes no other members"),
        Some("socks5") => {
            if members
                .keys()
                .any(|key| !matches!(key.as_str(), "mode" | "ip" | "port"))
            {
                return Err("network mode socks5 takes mode, ip and port only");
            }
            // An IPv4-mapped address is judged, and used, as the IPv4
            // address it maps.
            let ip = members
                .get("ip")
                .and_then(Value::as_str)
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                .map(|ip| ip.to_canonical())
                .ok_or("network.ip must be an IPv4 or IPv6 address, written plainly")?;
            if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::from([255, 255, 255, 255])
            {
                return Err("network.ip can't be unspecified, multicast or broadcast");
            }
            let port = members
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or("network.port must be an integer from 1 to 65535")?;
            Ok(NetworkPolicy::Socks5 {
                proxy: SocketAddr::new(ip, port),
            })
        }
        Some(_) => Err("network.mode must be direct or socks5"),
        None => Err("network.mode must be a string"),
    }
}

/// Checks a configured endpoint (a delegated router, or the DoH endpoint):
/// an `http` or `https` URL, read as the gate reads a configured endpoint
/// (WHATWG, ASCII, no userinfo), with a host it classifies, and no
/// fragment. Configuration main sends, not page input.
pub fn endpoint_ok(endpoint: &str) -> bool {
    endpoint.len() <= MAX_ENDPOINT_LEN
        && endpoint.bytes().all(|b| b.is_ascii_graphic())
        && parse_url(endpoint).is_ok_and(|url| {
            url.fragment().is_none() && ConfiguredTargets::new().add_url(&url).is_ok()
        })
}

/// The longest configured endpoint.
pub const MAX_ENDPOINT_LEN: usize = 2048;

/// Whether `endpoint` (one [`endpoint_ok`] accepted) is an onion's, which
/// only `socks5` can reach.
pub fn is_onion(endpoint: &str) -> bool {
    parse_url(endpoint)
        .ok()
        .and_then(|url| {
            freedom_ipfs_gateway::net::gate::classify_url(&url)
                .ok()
                .map(|target| matches!(target.target, Target::Onion(_)))
        })
        .unwrap_or(false)
}

/// The instance's network: upstream's policy for `policy`, with the
/// delegated routers and the DoH endpoint as its configured targets, and a
/// capability of its own. The endpoints are ones `ipfs.start`'s checks
/// accepted; anything upstream still refuses is a fixed message.
pub fn network(
    policy: NetworkPolicy,
    routers: &[String],
    doh_endpoint: &str,
) -> Result<Network, &'static str> {
    let mut configured = ConfiguredTargets::new();
    for router in routers {
        let url = parse_url(router).map_err(|_| "a delegated router can't be configured")?;
        configured
            .add_url(&url)
            .map_err(|_| "a delegated router can't be configured")?;
    }
    let doh = parse_url(doh_endpoint).map_err(|_| "the DoH endpoint can't be configured")?;
    let upstream = match policy {
        NetworkPolicy::Direct => {
            freedom_ipfs_gateway::NetworkPolicy::direct(configured, doh, Addresses::Unchecked)
        }
        NetworkPolicy::Socks5 { proxy } => {
            freedom_ipfs_gateway::NetworkPolicy::socks5(proxy, configured, doh)
        }
    }
    .map_err(|_| "the network policy can't be built")?;
    Network::new(upstream).map_err(|_| "the network can't be built")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn direct_and_socks5_are_accepted() {
        assert_eq!(
            parse(&json!({ "mode": "direct" })),
            Ok(NetworkPolicy::Direct)
        );
        for (ip, port) in [
            ("127.0.0.1", 9150),
            ("192.168.1.5", 9050),
            ("::1", 1),
            ("fd00::5", 65535),
        ] {
            assert_eq!(
                parse(&json!({ "mode": "socks5", "ip": ip, "port": port })),
                Ok(NetworkPolicy::Socks5 {
                    proxy: SocketAddr::new(ip.parse().unwrap(), port)
                }),
                "{ip}"
            );
        }
        // An IPv4-mapped address is the IPv4 address it maps.
        for (mapped, ip) in [
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("::ffff:7f00:1", "127.0.0.1"),
            ("::ffff:192.168.1.5", "192.168.1.5"),
        ] {
            assert_eq!(
                parse(&json!({ "mode": "socks5", "ip": mapped, "port": 9150 })),
                Ok(NetworkPolicy::Socks5 {
                    proxy: SocketAddr::new(ip.parse().unwrap(), 9150)
                }),
                "{mapped}"
            );
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for refused in [
            // Not an object, or no mode.
            json!("direct"),
            Value::Null,
            json!({}),
            json!({ "mode": 1 }),
            json!({ "mode": "tor" }),
            json!({ "mode": "direct", "ip": "127.0.0.1" }),
            // An address written any other way than plainly: shorthand,
            // hex, octal, brackets, a zone, spaces, a name.
            json!({ "mode": "socks5", "ip": "127.1", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "0x7f.0.0.1", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "0177.0.0.1", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "[::1]", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "fe80::1%eth0", "port": 9150 }),
            json!({ "mode": "socks5", "ip": " 127.0.0.1", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "localhost", "port": 9150 }),
            json!({ "mode": "socks5", "ip": 2130706433, "port": 9150 }),
            // Addresses a proxy can't be at.
            json!({ "mode": "socks5", "ip": "0.0.0.0", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "::", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "224.0.0.1", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "ff02::1", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "255.255.255.255", "port": 9150 }),
            // The same, IPv4-mapped, dotted and in hex.
            json!({ "mode": "socks5", "ip": "::ffff:0.0.0.0", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "::ffff:0:0", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "::ffff:224.0.0.1", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "::ffff:e000:1", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "::ffff:255.255.255.255", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "::ffff:ffff:ffff", "port": 9150 }),
            // Ports.
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 0 }),
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 65536 }),
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": -1 }),
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 1.5 }),
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": "9150" }),
            // Missing members, and credentials, which 0007 doesn't take.
            json!({ "mode": "socks5", "port": 9150 }),
            json!({ "mode": "socks5", "ip": "127.0.0.1" }),
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9150, "username": "u" }),
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9150, "password": "p" }),
        ] {
            assert!(parse(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_refusal_never_quotes_its_input() {
        let marker = "q7x9marker";
        for refused in [
            json!({ "mode": marker }),
            json!({ "mode": "socks5", "ip": marker, "port": 9150 }),
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9150, marker: 1 }),
        ] {
            let message = parse(&refused).unwrap_err();
            assert!(!message.contains(marker), "{message}");
        }
    }

    #[test]
    fn endpoints_are_read_as_the_gate_reads_a_configured_one() {
        for accepted in [
            "https://delegated-ipfs.dev/routing/v1",
            "http://127.0.0.1:5001/routing/v1",
            "https://cloudflare-dns.com/dns-query",
            "http://[::1]:8080/",
            "https://router.onion/routing/v1",
        ] {
            assert!(endpoint_ok(accepted), "{accepted}");
        }
        for refused in [
            "ftp://x",
            "https://",
            "https://a b",
            "https://user:pw@delegated-ipfs.dev/",
            "https://user@delegated-ipfs.dev/",
            "https://delegated-ipfs.dev/routing/v1#fragment",
            "https://dele%67ated-ipfs.dev/",
            "https://dé.example/",
            "https://a..b/",
            " https://delegated-ipfs.dev/",
            "javascript:alert(1)",
        ] {
            assert!(!endpoint_ok(refused), "{refused}");
        }
        assert!(!endpoint_ok(&format!("https://a/{}", "x".repeat(2048))));
        assert!(is_onion("https://router.onion/routing/v1"));
        assert!(is_onion("http://WWW.Router.ONION./"));
        assert!(!is_onion("https://delegated-ipfs.dev/routing/v1"));
    }

    #[test]
    fn the_network_is_built_for_the_policy() {
        let routers = ["https://delegated-ipfs.dev/routing/v1".to_string()];
        let doh = "https://cloudflare-dns.com/dns-query";
        let direct = network(NetworkPolicy::Direct, &routers, doh).unwrap();
        assert!(matches!(
            direct.policy().mode(),
            freedom_ipfs_gateway::net::Mode::Direct(_)
        ));
        assert_eq!(direct.policy().doh(), Some(doh));
        let configured = direct.policy().configured().unwrap();
        assert!(configured.contains(&Target::Name("delegated-ipfs.dev".into()), 443));
        assert!(configured.contains(&Target::Name("cloudflare-dns.com".into()), 443));

        let proxy: SocketAddr = "127.0.0.1:9150".parse().unwrap();
        let socks5 = network(NetworkPolicy::Socks5 { proxy }, &routers, doh).unwrap();
        assert!(matches!(
            socks5.policy().mode(),
            freedom_ipfs_gateway::net::Mode::Socks5(_)
        ));
        // The proxy is the transport, not a configured target.
        assert!(
            !socks5
                .policy()
                .configured()
                .unwrap()
                .contains(&Target::Ip(proxy.ip()), proxy.port())
        );
        // Each network has a capability of its own.
        direct.revoke();
        assert!(!socks5.capability().is_revoked());
    }
}
