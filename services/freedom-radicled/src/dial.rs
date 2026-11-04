//! The service's dial gate (design 0008, "Network policy", "Modes" and "The
//! address policy"): what the node may connect to, and how it resolves
//! names. heartwood asks it of every peer it dials and every address a peer
//! announces (heartwood item 11's `Gate`), through libradicle's `Routing`.
//!
//! - **One table and one classifier serve both services:** 0007's, as
//!   freedom-ipfs-addr ([`classify_host`], [`check_address`]).
//! - **Untrusted targets,** the addresses learned from peers, pass only at a
//!   globally reachable unicast address. That leaves out loopback, private,
//!   link-local, shared, multicast, documentation and reserved blocks, and
//!   the IPv6 forms that embed one. In `direct` mode, IPv6 outside the
//!   fixed forms waits for the network's NAT64 prefixes ([`Nat64`]).
//! - **Configured targets** are exempt by exact host and port: the profile's
//!   `preferredSeeds` and `connect` peers, so that a user's LAN seed keeps
//!   working. The shipped seed book's seeds are public names, which the
//!   policy passes anyway.
//! - **Names:**
//!   - **`direct`:** a name is resolved once, through the system's resolver,
//!     and heartwood connects to an answer this gate passes;
//!   - **`socks5`:** a name is resolved through the proxy's `RESOLVE`
//!     (Arti's), with credentials of the process's own, and its answer is
//!     checked the same way;
//!   - in both, a failed or empty answer, or one whose every address is
//!     refused, fails the dial, and no proxy is handed the name
//!     ([`Gate::proxy_resolves_names`] is false).
//! - **Onion names** are never resolved here. In `direct` mode heartwood
//!   drops them before any socket (`onion: Drop`); in `socks5` mode they
//!   take heartwood's onion route to the proxy, as names.
//! - **Stream isolation** under `socks5` is libradicle's: its `Routing`
//!   wraps this gate in one that isolates each remote node's streams.

use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use fc_service::network::NetworkPolicy;
use freedom_ipfs_addr::{ConfiguredTargets, Nat64State, Target, check_address, classify_host};
use freedom_ipfs_socks::Credentials;
use freedom_ipfs_socks::blocking::Client;
use radicle::node::config::{AddressConfig, ConnectAddress};
use radicle::node::dial::Gate;
use radicle::node::{Address, HostName};

/// How long a dial waits for its name to resolve.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// The NAT64 state the gate judges IPv6 addresses by, as discovery
/// publishes it.
#[derive(Clone)]
pub struct Nat64(Arc<RwLock<Nat64State>>);

impl Nat64 {
    /// A state discovery hasn't settled yet: every IPv6 address but an
    /// IPv4-mapped one waits for it.
    pub fn pending() -> Self {
        Self(Arc::new(RwLock::new(Nat64State::Pending)))
    }

    /// A state that never changes: `socks5` mode's, where the proxy's exit
    /// makes every connection, so the local network's prefixes don't apply.
    pub fn fixed(state: Nat64State) -> Self {
        Self(Arc::new(RwLock::new(state)))
    }

    /// Publishes `state`, discovery's latest.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "rad.start runs discovery, a later step")
    )]
    pub fn publish(&self, state: Nat64State) {
        *self.0.write().unwrap_or_else(|p| p.into_inner()) = state;
    }

    fn get(&self) -> Nat64State {
        self.0.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// How names are resolved.
enum Resolver {
    /// The C library's resolver (`direct`).
    System,
    /// The proxy's `RESOLVE` (`socks5`).
    Proxy(Client),
    /// Fixed answers, for tests.
    #[cfg(test)]
    Fixed(std::collections::HashMap<String, Vec<std::net::IpAddr>>),
}

/// The dial gate.
pub struct DialGate {
    resolver: Resolver,
    configured: ConfiguredTargets,
    nat64: Nat64,
}

impl fmt::Debug for DialGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No target or credential.
        f.debug_struct("DialGate").finish_non_exhaustive()
    }
}

/// Why the gate couldn't be made.
#[derive(Debug)]
pub enum Error {
    /// The OS's randomness, for the proxy credentials, failed.
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => f.write_str("the OS random number generator failed"),
        }
    }
}

/// The routing the node gets under `policy`: its gate, its proxy and its
/// onion route, in memory over `config.json` (0008, "Every routing field is
/// set in memory"). `configured` are the profile's own seeds and peers.
///
/// heartwood reaches the proxy and the onion route without asking the gate,
/// so an isolated node (`Options::isolated`) must have neither: libradicle
/// drops both, whatever this routing says (libradicle#26).
pub fn routing(
    policy: &NetworkPolicy,
    configured: &[ConnectAddress],
    nat64: Nat64,
) -> Result<libradicle::Routing, Error> {
    let configured = configured_targets(configured);
    let (resolver, proxy, onion) = match policy {
        NetworkPolicy::Direct => (Resolver::System, None, AddressConfig::Drop),
        NetworkPolicy::Socks5 { proxy } => {
            let credentials = Credentials::new(|bytes| {
                getrandom::fill(bytes).map_err(|_| freedom_ipfs_socks::RandomFailed)
            })
            .map_err(|_| Error::Random)?;
            (
                Resolver::Proxy(Client::new(*proxy, credentials)),
                Some(*proxy),
                AddressConfig::Proxy { address: *proxy },
            )
        }
    };
    Ok(libradicle::Routing {
        proxy,
        onion,
        gate: Arc::new(DialGate {
            resolver,
            configured,
            nat64,
        }),
    })
}

/// The configured targets: each seed's or peer's host and port. An onion,
/// an I2P address or a name that doesn't classify configures nothing: the
/// exemption is for what this gate judges.
fn configured_targets(addresses: &[ConnectAddress]) -> ConfiguredTargets {
    let mut configured = ConfiguredTargets::new();
    for address in addresses {
        let addr = &address.addr;
        match addr.host() {
            HostName::Ip(ip) => configured.add_endpoint(SocketAddr::new(*ip, addr.port())),
            HostName::Dns(name) => {
                if let Ok(url) =
                    freedom_ipfs_addr::parse_url(&format!("http://{name}:{}/", addr.port()))
                {
                    let _ = configured.add_url(&url);
                }
            }
            _ => {}
        }
    }
    configured
}

impl DialGate {
    /// Whether `target` is configured, at its port.
    fn configured(&self, target: &Address) -> bool {
        let class = match target.host() {
            HostName::Ip(ip) => Target::Ip(freedom_ipfs_addr::canonical(*ip)),
            HostName::Dns(name) => match classify_host(name) {
                Ok(class) => class,
                Err(_) => return false,
            },
            _ => return false,
        };
        self.configured.contains(&class, target.port())
    }
}

fn refused(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, why)
}

impl Gate for DialGate {
    fn allows(&self, target: &Address, addr: &SocketAddr) -> bool {
        if self.configured(target) {
            return true;
        }
        check_address(addr.ip(), &self.nat64.get()).is_ok()
    }

    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let name = match classify_host(host) {
            Ok(Target::Name(name)) => name,
            Ok(Target::Ip(ip)) => return Ok(vec![SocketAddr::new(ip, port)]),
            Ok(Target::Onion(_)) => return Err(refused("an onion name isn't resolved")),
            Err(_) => return Err(refused("the host doesn't classify")),
        };
        let answer: Vec<SocketAddr> = match &self.resolver {
            Resolver::System => (name.as_str(), port).to_socket_addrs()?.collect(),
            Resolver::Proxy(client) => {
                let ip = client
                    .resolve(&name, Instant::now() + RESOLVE_TIMEOUT)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                vec![SocketAddr::new(ip, port)]
            }
            #[cfg(test)]
            Resolver::Fixed(answers) => answers
                .get(&name)
                .into_iter()
                .flatten()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect(),
        };
        // An empty answer fails the dial: heartwood never hands the proxy
        // the name instead.
        if answer.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no address"));
        }
        Ok(answer)
    }

    fn resolve_timeout(&self) -> Duration {
        RESOLVE_TIMEOUT
    }

    fn proxy_resolves_names(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
