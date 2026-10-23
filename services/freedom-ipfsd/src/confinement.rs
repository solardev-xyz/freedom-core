//! The process's confinement policy (design 0010, "What each service
//! needs"). Apart from the rest of the service, so a test confines a process
//! of its own with exactly this policy (`tests/nat64_confined.rs`): it uses
//! fc-service and fc-nat64 alone.

use std::path::{Path, PathBuf};

use fc_service::confine;
use fc_service::network::NetworkPolicy;

/// The policy: the data directory read-write (`read_write`; none for the
/// ephemeral process), NAT64 discovery's resolver files read-only beside the
/// system's own ([`resolver_grants`]), and TCP to the proxy's port alone in
/// `socks5` mode, keeping `descriptors` (the lock).
///
/// - **`system_resolver`:** freedom-ipfs-net resolves names through the C
///   library (`getaddrinfo`), so the report says whether that reaches DNS.
/// - **`interface_index`:** NAT64 discovery looks up a link-local
///   resolver's named zone (`fe80::1%eth0`) through `SIOCGIFINDEX`, the one
///   `ioctl` this adds. Sysfs's `/sys/class/net/<name>` resolves into
///   `/sys/devices`, which no grant should cover.
pub fn policy(
    read_write: Vec<PathBuf>,
    network: &NetworkPolicy,
    descriptors: Vec<i32>,
) -> confine::Policy {
    confine::Policy {
        read_write,
        read_only: resolver_grants(),
        refer: false,
        min_abi: 1,
        network: network.confinement(),
        system_resolver: true,
        descriptors,
        interface_index: true,
    }
}

/// The read-only grants for the files discovery reads its resolvers from:
/// on Linux, `/etc/resolv.conf` and systemd-resolved's export, each where it
/// really lives. A file in `/etc` itself is granted alone, any other by its
/// directory, so a replacement there stays readable. One that can't be read
/// after a replacement makes discovery `unknown` (fc-nat64's
/// `Learned::Unreadable`). Elsewhere, none.
pub fn resolver_grants() -> Vec<PathBuf> {
    let mut grants = Vec::new();
    if cfg!(target_os = "linux") {
        for file in fc_nat64::resolvers::LINUX_FILES {
            if let Some(grant) = confine::resolver_grant(Path::new(file))
                && !grants.contains(&grant)
            {
                grants.push(grant);
            }
        }
    }
    grants
}
