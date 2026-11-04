//! The network policy an instance runs under (design 0007, "Network
//! policy", "Modes"): the process's, from `--network` at spawn
//! ([`NetworkPolicy`], `fc_service::network`), fixed for its life, so
//! confinement applies it before `ipfs.hello` (design 0010).
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

use freedom_ipfs_gateway::net::gate::{ConfiguredTargets, Target, parse_url};
use freedom_ipfs_gateway::net::{Addresses, DnsConfig, Nat64Handle, Network};

use crate::testhooks;

pub use fc_service::network::NetworkPolicy;

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
/// capability of its own. Under `direct`, untrusted addresses are checked
/// against the address table, with what the process's NAT64 discovery
/// knows (`nat64`); configured targets stay exempt. The endpoints are ones
/// `ipfs.start`'s checks accepted; anything upstream still refuses is a
/// fixed message.
///
/// No address is exempt for being on a local network: providers there are
/// refused unless configured (design 0007's open question 5). An opt-in
/// would be one more `Addresses` choice here.
///
/// Under `direct`, its own lookups (the gate's HTTP resolver's, libp2p's
/// DNS layer's and `/dnsaddr`'s) ask `dns`, the process's configuration
/// (`dns.rs`), which `confinement.resolution` reports; without one, the
/// system's, read now.
pub fn network(
    policy: NetworkPolicy,
    routers: &[String],
    doh_endpoint: &str,
    nat64: Nat64Handle,
    dns: Option<&DnsConfig>,
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
        NetworkPolicy::Direct => freedom_ipfs_gateway::NetworkPolicy::direct(
            configured,
            doh,
            testhooks::direct_addresses(Addresses::Checked(nat64)),
        ),
        NetworkPolicy::Socks5 { proxy } => {
            freedom_ipfs_gateway::NetworkPolicy::socks5(proxy, configured, doh)
        }
    }
    .map_err(|_| "the network policy can't be built")?;
    match dns {
        Some(dns) => Network::with_dns(upstream, dns.clone()),
        None => Network::new(upstream),
    }
    .map_err(|_| "the network can't be built")
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

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
        let nat64 = || Nat64Handle::fixed(freedom_ipfs_gateway::net::gate::Nat64State::NONE);
        let direct = network(NetworkPolicy::Direct, &routers, doh, nat64(), None).unwrap();
        // Untrusted addresses are checked against the address table, with
        // what NAT64 discovery knows.
        assert!(matches!(
            direct.policy().mode(),
            freedom_ipfs_gateway::net::Mode::Direct(direct)
                if matches!(direct.addresses, Addresses::Checked(_))
        ));
        assert_eq!(direct.policy().doh(), Some(doh));
        let configured = direct.policy().configured().unwrap();
        assert!(configured.contains(&Target::Name("delegated-ipfs.dev".into()), 443));
        assert!(configured.contains(&Target::Name("cloudflare-dns.com".into()), 443));

        let proxy: SocketAddr = "127.0.0.1:9150".parse().unwrap();
        let socks5 = network(
            NetworkPolicy::Socks5 { proxy },
            &routers,
            doh,
            nat64(),
            None,
        )
        .unwrap();
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
