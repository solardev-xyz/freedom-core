//! The service's confinement (design 0010): its grant and policy, applied by
//! `fc_service::confine` once, on the main thread, **while it is the
//! process's only thread**.
//!
//! - **Before it:** the panic hook and the entry's one re-exec
//!   (`fc_service::confine::clean_entry`), hardening, the arguments, the
//!   environment ([`crate::env`]), the gate, and [`Grant::open`].
//! - **After it:** logging's writer, the connection's threads, the
//!   watchdogs and the pools, then the handshake.
//!
//! The grant (0010, "What each service needs"): the Radicle home and the
//! service's own `HOME` directory (0008, "Spawn and lock"), read and write,
//! with renames and links across them (`refer`: libgit2 links each loose
//! object into place). Landlock ABI 2 at least, which has `refer`: below it,
//! no Landlock rules and `files` unavailable.

use std::io;
use std::path::{Path, PathBuf};

use fc_service::confine::{self, Invalid, Policy, Report};
use fc_service::network::NetworkPolicy;

/// The lowest Landlock ABI the service's file rules work under: `refer`
/// came with ABI 2.
const MIN_ABI: u32 = 2;

/// The directories the service may use.
#[derive(Debug)]
pub struct Grant {
    /// The canonical Radicle home, under the gate.
    pub home: PathBuf,
    /// The service's own `HOME` (0008: an empty directory the service
    /// owns), canonical.
    pub own_home: PathBuf,
}

impl Grant {
    /// The grant for `home` (already canonical, from the gate) and
    /// `own_home`; both must be directories.
    pub fn open(home: &Path, own_home: &Path) -> io::Result<Self> {
        let own_home = std::fs::canonicalize(own_home)?;
        for dir in [home, own_home.as_path()] {
            if !std::fs::metadata(dir)?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "not a directory",
                ));
            }
        }
        Ok(Self {
            home: home.to_path_buf(),
            own_home,
        })
    }

    /// The policy for this grant, under `network`, keeping `descriptors`
    /// (the gate's lock). The Radicle node resolves names through the C
    /// library in `direct` mode (0008: std's `to_socket_addrs`, glibc's
    /// `getaddrinfo`), so the report says whether that reaches DNS.
    ///
    /// **NAT64 discovery** runs in `direct` mode alone, for the node's life
    /// (`rad.start` holds its lease; design 0010, "NAT64 prefix
    /// discovery"), as freedom-ipfsd's does: the files that list the
    /// resolvers it asks, read-only, each where it really lives
    /// ([`nat64_grants`]), and `SIOCGIFINDEX` (`interface_index`) for a
    /// link-local resolver's named zone. In `socks5` mode it learns
    /// nothing, so neither is granted.
    pub fn policy(&self, network: &NetworkPolicy, descriptors: Vec<i32>) -> Policy {
        let direct = matches!(network, NetworkPolicy::Direct);
        Policy {
            read_write: vec![self.home.clone(), self.own_home.clone()],
            read_only: if direct { nat64_grants() } else { Vec::new() },
            refer: true,
            min_abi: MIN_ABI,
            network: network.confinement(),
            resolver: confine::Resolver::System,
            descriptors,
            interface_index: direct,
        }
    }
}

/// The read-only grants for the files NAT64 discovery reads its resolvers
/// from, as freedom-ipfsd's: on Linux, `/etc/resolv.conf` and
/// systemd-resolved's export; on macOS, the file `/etc/resolv.conf` names.
/// Each is granted where it really lives (a file in `/etc` alone, any other
/// by its directory), so a replacement there stays readable.
fn nat64_grants() -> Vec<PathBuf> {
    let files: &[&str] = if cfg!(target_os = "linux") {
        &fc_nat64::resolvers::LINUX_FILES
    } else if cfg!(target_os = "macos") {
        &fc_nat64::resolvers::MACOS_FILES
    } else {
        &[]
    };
    let mut grants = Vec::new();
    for file in files {
        if let Some(grant) = confine::resolver_grant(Path::new(file))
            && !grants.contains(&grant)
        {
            grants.push(grant);
        }
    }
    grants
}

/// Confines the process to `grant` under `network`. With the test hooks, it
/// first reports the threads and descriptors the process has here, so a test
/// proves the point is reached single-threaded, holding stdio and the lock.
pub fn confine(
    grant: &Grant,
    network: &NetworkPolicy,
    descriptors: Vec<i32>,
) -> Result<Report, Invalid> {
    crate::testhooks::at_confinement_point();
    confine::confine(&grant.policy(network, descriptors))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn nat64_discovery_is_granted_in_direct_mode_alone() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant::open(dir.path(), dir.path()).unwrap();
        let direct = grant.policy(&NetworkPolicy::Direct, vec![]);
        assert!(direct.interface_index);
        assert_eq!(direct.read_only, nat64_grants());
        let socks5 = grant.policy(
            &NetworkPolicy::Socks5 {
                proxy: "127.0.0.1:9050".parse().unwrap(),
            },
            vec![],
        );
        assert!(!socks5.interface_index);
        assert!(socks5.read_only.is_empty());
        // Both read and write the home and the service's own HOME alone.
        assert_eq!(direct.read_write, socks5.read_write);
    }
}
