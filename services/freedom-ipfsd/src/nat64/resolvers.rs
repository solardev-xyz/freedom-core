//! The resolvers discovery asks (design 0007, "Network-specific NAT64
//! prefixes", *Which resolvers, per OS*): the ones each interface learned,
//! read where the OS keeps them, not only the effective list, since a
//! manual setting, a VPN's resolver or a local recursive resolver can stand
//! in front of an interface's own. Only an access network's own DNS64
//! synthesizes for it (RFC 8880 §7.1).
//!
//! - **Linux** (and any other Unix but macOS): `/etc/resolv.conf`, and the
//!   servers systemd-resolved exports to `/run/systemd/resolve/resolv.conf`
//!   when it runs. Files only, by choice: resolved's D-Bus API isn't read.
//! - **macOS:** each network service's DNS state in the SystemConfiguration
//!   dynamic store (`State:/Network/Service/<id>/DNS`), and
//!   `/etc/resolv.conf`.
//! - **Windows:** each adapter that is up: its DNS servers
//!   (`GetAdaptersAddresses`), and the servers DHCP gave it
//!   (`DhcpNameServer` under its `Tcpip` parameters), which a manual
//!   setting overrides in the first list.
//!
//! Every resolver is asked on port 53. A link-local IPv6 resolver needs its
//! interface: a zone that names one the OS can't find, or none, leaves it
//! [`Learned::Unaskable`], which discovery counts as a resolver that failed.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// DNS's port.
pub const PORT: u16 = 53;

/// A resolver the OS lists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Learned {
    /// One to ask, at this address.
    Ask(SocketAddr),
    /// A link-local IPv6 resolver whose interface can't be found (its
    /// address, as listed).
    Unaskable(String),
}

/// The resolvers the OS lists now, each once, in the order found.
pub fn learned() -> Vec<Learned> {
    dedup(os::learned())
}

/// Each resolver once, in the order first found.
pub fn dedup(learned: impl IntoIterator<Item = Learned>) -> Vec<Learned> {
    let mut seen = Vec::new();
    for resolver in learned {
        if !seen.contains(&resolver) {
            seen.push(resolver);
        }
    }
    seen
}

/// The `nameserver` lines of a resolv.conf, in order: each address and its
/// zone (`fe80::1%eth0`), if it has one. Comments (`#`, `;`) and other
/// lines are skipped, as is an address that doesn't parse.
pub fn resolv_conf(text: &str) -> Vec<(IpAddr, Option<String>)> {
    text.lines()
        .filter_map(|line| {
            let line = line.split(['#', ';']).next().unwrap_or_default();
            let mut words = line.split_whitespace();
            if words.next() != Some("nameserver") {
                return None;
            }
            address(words.next()?)
        })
        .collect()
}

/// An address as a resolver list writes it, with its zone, if any.
pub fn address(text: &str) -> Option<(IpAddr, Option<String>)> {
    let (ip, zone) = match text.split_once('%') {
        Some((ip, zone)) => (ip, Some(zone.to_string())),
        None => (text, None),
    };
    Some((ip.parse().ok()?, zone.filter(|zone| !zone.is_empty())))
}

/// The resolver at `ip`, with `zone` (a number, or an interface's name that
/// `index` finds) when it is link-local IPv6. Elsewhere a zone is ignored.
pub fn learn(ip: IpAddr, zone: Option<&str>, index: impl Fn(&str) -> Option<u32>) -> Learned {
    match ip {
        IpAddr::V6(v6) if is_link_local(v6) => {
            let scope = zone.and_then(|zone| zone.parse::<u32>().ok().or_else(|| index(zone)));
            match scope {
                Some(scope) if scope != 0 => {
                    Learned::Ask(SocketAddr::V6(SocketAddrV6::new(v6, PORT, 0, scope)))
                }
                _ => Learned::Unaskable(match zone {
                    Some(zone) => format!("{v6}%{zone}"),
                    None => v6.to_string(),
                }),
            }
        }
        ip => Learned::Ask(SocketAddr::new(ip, PORT)),
    }
}

/// `fe80::/10`.
fn is_link_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// The servers a Windows `DhcpNameServer` value lists, separated by spaces
/// or commas.
pub fn dhcp_name_servers(value: &str) -> Vec<(IpAddr, Option<String>)> {
    value
        .split([' ', ','])
        .filter(|item| !item.is_empty())
        .filter_map(address)
        .collect()
}

/// The `ServerAddresses` a macOS DNS state lists, from its XML property
/// list: the strings of the array after that key.
pub fn server_addresses(plist: &str) -> Vec<(IpAddr, Option<String>)> {
    let Some((_, after)) = plist.split_once("<key>ServerAddresses</key>") else {
        return Vec::new();
    };
    let after = after.trim_start();
    let Some(array) = after
        .strip_prefix("<array>")
        .and_then(|array| array.split_once("</array>"))
        .map(|(array, _)| array)
    else {
        return Vec::new();
    };
    array
        .split("<string>")
        .skip(1)
        .filter_map(|item| item.split_once("</string>").map(|(text, _)| text.trim()))
        .filter_map(address)
        .collect()
}

#[cfg(not(any(target_os = "macos", windows)))]
mod os {
    use super::{Learned, learn, resolv_conf};

    /// The files read: the effective list, and what systemd-resolved
    /// exports when it runs.
    const FILES: [&str; 2] = ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"];

    pub fn learned() -> Vec<Learned> {
        FILES
            .iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .flat_map(|text| resolv_conf(&text))
            .map(|(ip, zone)| learn(ip, zone.as_deref(), index))
            .collect()
    }

    /// An interface's index, by its name, from sysfs.
    fn index(name: &str) -> Option<u32> {
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return None;
        }
        std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }
}

#[cfg(target_os = "macos")]
mod os {
    use super::{Learned, learn, resolv_conf, server_addresses};
    use system_configuration::core_foundation::propertylist::{
        create_data, kCFPropertyListXMLFormat_v1_0,
    };
    use system_configuration::dynamic_store::SCDynamicStoreBuilder;

    /// The network services' DNS state.
    const PATTERN: &str = "State:/Network/Service/[^/]+/DNS";

    pub fn learned() -> Vec<Learned> {
        let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
        let index = |name: &str| {
            interfaces
                .iter()
                .find(|interface| interface.name == name)
                .and_then(|interface| interface.index)
        };
        let mut found = dynamic_store(index);
        if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
            found.extend(
                resolv_conf(&text)
                    .into_iter()
                    .map(|(ip, zone)| learn(ip, zone.as_deref(), index)),
            );
        }
        found
    }

    /// The network services' resolvers, from the dynamic store.
    pub fn dynamic_store(index: impl Fn(&str) -> Option<u32>) -> Vec<Learned> {
        let mut found: Vec<Learned> = Vec::new();
        if let Some(store) = SCDynamicStoreBuilder::new("freedom-ipfsd").build()
            && let Some(keys) = store.get_keys(PATTERN)
        {
            for key in keys.iter() {
                let Some(state) = store.get(key.clone()) else {
                    continue;
                };
                // The state as XML: reading the dictionary directly needs
                // unsafe code, which this crate forbids.
                let Ok(xml) = create_data(state.as_CFTypeRef(), kCFPropertyListXMLFormat_v1_0)
                else {
                    continue;
                };
                let text = String::from_utf8_lossy(xml.bytes()).into_owned();
                found.extend(
                    server_addresses(&text)
                        .into_iter()
                        .map(|(ip, zone)| learn(ip, zone.as_deref(), &index)),
                );
            }
        }
        found
    }
}

#[cfg(windows)]
mod os {
    use super::{Learned, dhcp_name_servers, learn};
    use ipconfig::OperStatus;
    use std::net::IpAddr;

    pub fn learned() -> Vec<Learned> {
        let Ok(adapters) = ipconfig::get_adapters() else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for adapter in adapters
            .iter()
            .filter(|adapter| adapter.oper_status() == OperStatus::IfOperStatusUp)
        {
            // An adapter's link-local resolver is on its own interface.
            let scope = adapter.ipv6_if_index();
            let index = |_: &str| Some(scope);
            let zone = scope.to_string();
            let ip_zone = |ip: &IpAddr| match ip {
                IpAddr::V6(_) => Some(zone.as_str()),
                IpAddr::V4(_) => None,
            };
            for ip in adapter.dns_servers() {
                found.push(learn(*ip, ip_zone(ip), index));
            }
            let path = format!(
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}",
                adapter.adapter_name()
            );
            if let Ok(value) = windows_registry::LOCAL_MACHINE
                .open(&path)
                .and_then(|key| key.get_string("DhcpNameServer"))
            {
                for (ip, _) in dhcp_name_servers(&value) {
                    found.push(learn(ip, ip_zone(&ip), index));
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn resolv_conf_lists_its_nameservers_in_order() {
        let text = "\
# Generated by NetworkManager
search lan
nameserver 192.168.1.1
nameserver   2001:db8::53   # trailing comment
; nameserver 10.0.0.1
nameserver fe80::1%eth0
nameserver not-an-address
options edns0
nameserver 9.9.9.9;comment
";
        assert_eq!(
            resolv_conf(text),
            vec![
                (ip("192.168.1.1"), None),
                (ip("2001:db8::53"), None),
                (ip("fe80::1"), Some("eth0".to_string())),
                (ip("9.9.9.9"), None),
            ]
        );
        assert!(resolv_conf("").is_empty());
    }

    #[test]
    fn a_link_local_resolver_needs_its_interface() {
        let index = |name: &str| (name == "eth0").then_some(2);
        assert_eq!(
            learn(ip("fe80::1"), Some("eth0"), index),
            Learned::Ask("[fe80::1%2]:53".parse().unwrap())
        );
        assert_eq!(
            learn(ip("fe80::1"), Some("7"), index),
            Learned::Ask("[fe80::1%7]:53".parse().unwrap())
        );
        assert_eq!(
            learn(ip("fe80::1"), Some("wlan9"), index),
            Learned::Unaskable("fe80::1%wlan9".to_string())
        );
        assert_eq!(
            learn(ip("fe80::1"), None, index),
            Learned::Unaskable("fe80::1".to_string())
        );
        assert_eq!(
            learn(ip("fe80::1"), Some("0"), index),
            Learned::Unaskable("fe80::1%0".to_string())
        );
        // Elsewhere a zone is ignored.
        assert_eq!(
            learn(ip("2001:db8::53"), Some("eth0"), index),
            Learned::Ask("[2001:db8::53]:53".parse().unwrap())
        );
        assert_eq!(
            learn(ip("127.0.0.53"), None, index),
            Learned::Ask("127.0.0.53:53".parse().unwrap())
        );
        // fec0:: isn't link-local.
        assert_eq!(
            learn(ip("febf::1"), None, index),
            Learned::Unaskable("febf::1".to_string())
        );
        assert_eq!(
            learn(ip("fec0::1"), None, index),
            Learned::Ask("[fec0::1]:53".parse().unwrap())
        );
    }

    #[test]
    fn a_resolver_is_listed_once() {
        let a = Learned::Ask("127.0.0.53:53".parse().unwrap());
        let b = Learned::Ask("192.168.1.1:53".parse().unwrap());
        assert_eq!(
            dedup([a.clone(), b.clone(), a.clone(), b.clone()]),
            vec![a, b]
        );
    }

    #[test]
    fn dhcp_name_server_values_split_on_spaces_and_commas() {
        assert_eq!(
            dhcp_name_servers("192.168.1.1 192.168.1.2,10.0.0.1 , bogus"),
            vec![
                (ip("192.168.1.1"), None),
                (ip("192.168.1.2"), None),
                (ip("10.0.0.1"), None),
            ]
        );
        assert!(dhcp_name_servers("").is_empty());
    }

    #[test]
    fn a_macos_dns_state_lists_its_server_addresses() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>DomainName</key>
	<string>lan</string>
	<key>ServerAddresses</key>
	<array>
		<string>192.168.1.1</string>
		<string>fe80::1%en0</string>
		<string>2001:db8::53</string>
	</array>
	<key>SearchDomains</key>
	<array>
		<string>10.0.0.9</string>
	</array>
</dict>
</plist>
"#;
        assert_eq!(
            server_addresses(plist),
            vec![
                (ip("192.168.1.1"), None),
                (ip("fe80::1"), Some("en0".to_string())),
                (ip("2001:db8::53"), None),
            ]
        );
        assert!(server_addresses("<plist><dict></dict></plist>").is_empty());
        assert!(server_addresses("<key>ServerAddresses</key><string>1.1.1.1</string>").is_empty());
    }

    /// The OS's list reads without failing; what it holds depends on the
    /// host. Where a host is known to have resolvers (CI's runners set
    /// `FREEDOM_IPFSD_TEST_OS_RESOLVERS`), the list has one, and on macOS
    /// the dynamic store alone does.
    #[test]
    fn the_os_list_reads() {
        let found = learned();
        for resolver in &found {
            match resolver {
                Learned::Ask(addr) => assert_eq!(addr.port(), PORT),
                Learned::Unaskable(text) => assert!(!text.is_empty()),
            }
        }
        if std::env::var_os("FREEDOM_IPFSD_TEST_OS_RESOLVERS").is_some() {
            assert!(!found.is_empty(), "the OS lists no resolver");
            #[cfg(target_os = "macos")]
            {
                let services = os::dynamic_store(|_| None);
                assert!(
                    !services.is_empty(),
                    "the dynamic store lists none: {found:?}"
                );
            }
        }
    }
}
