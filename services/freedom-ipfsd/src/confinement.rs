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
/// - **`resolver`:** freedom-ipfs-net resolves names with hickory over
///   `/etc/resolv.conf`'s servers, never through the C library's
///   `getaddrinfo` ([`confine::Resolver::ResolvConf`]): nothing of
///   `nsswitch.conf` or glibc's NSS sources is granted, and the report's
///   `resolution` says `resolv_conf`.
/// - **`interface_index`:** NAT64 discovery looks up a link-local
///   resolver's named zone (`fe80::1%eth0`) through `SIOCGIFINDEX`, the one
///   `ioctl` this adds, in `direct` mode alone: discovery runs only there.
///   Sysfs's `/sys/class/net/<name>` resolves into `/sys/devices`, which no
///   grant should cover.
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
        resolver: confine::Resolver::ResolvConf,
        descriptors,
        interface_index: matches!(network, NetworkPolicy::Direct),
    }
}

/// The read-only grants for the files discovery reads its resolvers from:
/// on Linux, `/etc/resolv.conf` and systemd-resolved's export, each where it
/// really lives. A file in `/etc` itself is granted alone, any other by its
/// directory, so a replacement there stays readable. One that can't be read
/// after a replacement makes discovery `unknown` (fc-nat64's
/// `Learned::Unreadable`). On macOS, the file `/etc/resolv.conf` names,
/// which Seatbelt matches by path, so a replacement stays readable.
/// Elsewhere, none.
pub fn resolver_grants() -> Vec<PathBuf> {
    let mut grants = Vec::new();
    let files: &[&str] = if cfg!(target_os = "linux") {
        &fc_nat64::resolvers::LINUX_FILES
    } else if cfg!(target_os = "macos") {
        &fc_nat64::resolvers::MACOS_FILES
    } else {
        &[]
    };
    for file in files {
        if let Some(grant) = confine::resolver_grant(Path::new(file))
            && !grants.contains(&grant)
        {
            grants.push(grant);
        }
    }
    grants
}
