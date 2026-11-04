//! The service's confinement (design 0010): its grant and policy, applied by
//! `fc_service::confine` once, on the main thread, **while it is the
//! process's only thread**.
//!
//! - **Before it:** the panic hook and the entry's one re-exec
//!   (`fc_service::confine::clean_entry`), hardening, the arguments, the
//!   environment ([`crate::env`]), the gate, and [`Grant::open`].
//! - **After it:** logging's writer, the connection's threads, the
//!   watchdogs, then the handshake.
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
    pub fn policy(&self, network: &NetworkPolicy, descriptors: Vec<i32>) -> Policy {
        Policy {
            read_write: vec![self.home.clone(), self.own_home.clone()],
            read_only: Vec::new(),
            refer: true,
            min_abi: MIN_ABI,
            network: network.confinement(),
            resolver: confine::Resolver::System,
            descriptors,
            // No NAT64 discovery here yet, so no interface lookups.
            interface_index: false,
        }
    }
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
