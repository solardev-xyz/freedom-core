//! The network policy a service is spawned with: `--network` (design 0007,
//! "Spawn"; 0008 takes the same forms). It is fixed for the process's life,
//! so [`crate::confine`] applies it before `hello`, and `hello` reports it
//! back ([`NetworkPolicy::to_json`]).
//!
//! ```text
//! --network direct
//! --network socks5:<ip>:<port>     an IPv4 address, or an IPv6 one in brackets
//! ```
//!
//! - **The address is written plainly:** no zone, no shorthand, no hex or
//!   octal. std's parsers refuse all of them. An IPv4-mapped IPv6 address
//!   is read as the IPv4 address it maps. It may not be unspecified,
//!   multicast or broadcast. Loopback and private addresses are allowed,
//!   since an external Tor may sit on the LAN.
//! - **The port** is 1 to 65535, in decimal digits: no sign, no leading
//!   zero.
//! - **No credentials:** a service makes each instance's own.
//! - **Anything else** is a usage error (exit 64).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde_json::{Value, json};

use crate::confine;

/// The process's network policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Direct connections, behind the service's own gate.
    Direct,
    /// Every connection through the SOCKS5 proxy at this endpoint.
    Socks5 { proxy: SocketAddr },
}

impl NetworkPolicy {
    /// Parses `--network`'s value; `None` is a usage error.
    pub fn parse(arg: &str) -> Option<NetworkPolicy> {
        if arg == "direct" {
            return Some(NetworkPolicy::Direct);
        }
        let endpoint = arg.strip_prefix("socks5:")?;
        let (ip, port) = match endpoint.strip_prefix('[') {
            Some(bracketed) => {
                let (ip, port) = bracketed.split_once("]:")?;
                (IpAddr::V6(ip.parse::<Ipv6Addr>().ok()?), port)
            }
            // Without brackets only IPv4: an IPv6 address's colons leave a
            // first part that isn't one.
            None => {
                let (ip, port) = endpoint.split_once(':')?;
                (IpAddr::V4(ip.parse::<Ipv4Addr>().ok()?), port)
            }
        };
        if port.is_empty() || port.starts_with('0') || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let port = port.parse::<u16>().ok()?;
        // Judged, and used, as the IPv4 address it maps.
        let ip = ip.to_canonical();
        if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
            return None;
        }
        Some(NetworkPolicy::Socks5 {
            proxy: SocketAddr::new(ip, port),
        })
    }

    /// The policy as `hello` reports it: `{ "mode": "direct" }`, or
    /// `{ "mode": "socks5", "ip": "127.0.0.1", "port": 9150 }`.
    pub fn to_json(&self) -> Value {
        match self {
            NetworkPolicy::Direct => json!({ "mode": "direct" }),
            NetworkPolicy::Socks5 { proxy } => json!({
                "mode": "socks5",
                "ip": proxy.ip().to_string(),
                "port": proxy.port(),
            }),
        }
    }

    /// What confinement enforces of it: in `socks5` mode, TCP to the
    /// proxy's port only (0010: Landlock's rules name ports only).
    pub fn confinement(&self) -> confine::Network {
        match self {
            NetworkPolicy::Direct => confine::Network::Direct,
            NetworkPolicy::Socks5 { proxy } => confine::Network::Socks5 {
                port: proxy.port(),
                loopback: proxy.ip().to_canonical().is_loopback(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks5(addr: &str) -> Option<NetworkPolicy> {
        Some(NetworkPolicy::Socks5 {
            proxy: addr.parse().unwrap(),
        })
    }

    #[test]
    fn the_forms_it_takes() {
        assert_eq!(NetworkPolicy::parse("direct"), Some(NetworkPolicy::Direct));
        assert_eq!(
            NetworkPolicy::parse("socks5:127.0.0.1:9150"),
            socks5("127.0.0.1:9150")
        );
        // A LAN proxy, an IPv6 one, and the highest port.
        assert_eq!(
            NetworkPolicy::parse("socks5:192.168.1.10:9050"),
            socks5("192.168.1.10:9050")
        );
        assert_eq!(
            NetworkPolicy::parse("socks5:[::1]:9150"),
            socks5("[::1]:9150")
        );
        assert_eq!(
            NetworkPolicy::parse("socks5:[fd00::5]:65535"),
            socks5("[fd00::5]:65535")
        );
        // An IPv4-mapped address is the IPv4 address it maps.
        assert_eq!(
            NetworkPolicy::parse("socks5:[::ffff:127.0.0.1]:9150"),
            socks5("127.0.0.1:9150")
        );
    }

    #[test]
    fn everything_else_is_a_usage_error() {
        for arg in [
            "",
            "Direct",
            "direct ",
            "tor",
            "socks5",
            "socks5:",
            // A name, not an address.
            "socks5:localhost:9150",
            // A zone.
            "socks5:[fe80::1%eth0]:9150",
            // Shorthand, octal and hex.
            "socks5:127.1:9150",
            "socks5:0127.0.0.1:9150",
            "socks5:0x7f.0.0.1:9150",
            // IPv6 without brackets, brackets around IPv4.
            "socks5:::1:9150",
            "socks5:fd00::5:9150",
            "socks5:[127.0.0.1]:9150",
            // Ports.
            "socks5:127.0.0.1",
            "socks5:127.0.0.1:",
            "socks5:127.0.0.1:0",
            "socks5:127.0.0.1:09150",
            "socks5:127.0.0.1:+9150",
            "socks5:127.0.0.1:65536",
            "socks5:127.0.0.1:9150:1",
            "socks5:[::1]9150",
            // Credentials.
            "socks5:user@127.0.0.1:9150",
            // Unspecified, multicast and broadcast.
            "socks5:0.0.0.0:9150",
            "socks5:[::]:9150",
            "socks5:224.0.0.1:9150",
            "socks5:[ff02::1]:9150",
            "socks5:255.255.255.255:9150",
            "socks5:[::ffff:0.0.0.0]:9150",
        ] {
            assert_eq!(NetworkPolicy::parse(arg), None, "{arg:?}");
        }
    }

    #[test]
    fn hello_reports_it_and_confinement_takes_its_port() {
        assert_eq!(NetworkPolicy::Direct.to_json(), json!({ "mode": "direct" }));
        let policy = NetworkPolicy::parse("socks5:[::1]:9150").unwrap();
        assert_eq!(
            policy.to_json(),
            json!({ "mode": "socks5", "ip": "::1", "port": 9150 })
        );
        assert_eq!(
            policy.confinement(),
            confine::Network::Socks5 {
                port: 9150,
                loopback: true
            }
        );
        // A LAN proxy, and an IPv4-mapped loopback one.
        assert_eq!(
            NetworkPolicy::parse("socks5:192.168.1.10:9150")
                .unwrap()
                .confinement(),
            confine::Network::Socks5 {
                port: 9150,
                loopback: false
            }
        );
        assert_eq!(
            NetworkPolicy::parse("socks5:[::ffff:127.0.0.1]:9150")
                .unwrap()
                .confinement(),
            confine::Network::Socks5 {
                port: 9150,
                loopback: true
            }
        );
        assert_eq!(
            NetworkPolicy::Direct.confinement(),
            confine::Network::Direct
        );
    }
}
