//! The Seatbelt profile for a [`Policy`] (design 0010, "macOS"): SBPL text,
//! the language of macOS's sandbox. It is undocumented; Apple's own
//! profiles are the reference, and Apple can change it.
//!
//! Generated and tested on every OS; applied on macOS
//! (`super::macos`). The text depends only on the policy's shape: every
//! path goes in as a parameter (`(param "RW_0")`), never as text, so no
//! path is ever quoted into the profile. Ports are digits.
//!
//! - **Denied by default,** with no `(import "system.sb")`: Apple's base
//!   profile allows many Mach services, and the profile allows only the
//!   channels the `ipc` property names.
//! - **Files:** the system's libraries and frameworks, read-only; the
//!   read-only grants; and in the read-write grants, reads, creating,
//!   writing (truncating included), unlinking and `ioctl`, plus hard links
//!   with `refer`. No mode, owner, flags, times or xattr change is allowed
//!   anywhere (`file-write-mode` and the rest stay denied). Metadata is
//!   readable only on each grant's ancestors, so other files' names and
//!   modes stay hidden.
//! - **Processes:** no exec and no fork (denied by default); signals and
//!   process information for the process itself only.
//! - **`sysctl`, by name only** ([`SYSCTLS`]): what std, tokio and the
//!   services read about the machine and the OS, after Chromium's
//!   `common.sb`. Nothing about other processes: `kern.proc` and
//!   `KERN_PROCARGS2`, which read another process's arguments and
//!   environment, stay denied. In `direct` mode, the routing sysctls too,
//!   for NAT64 discovery's interface list (`getifaddrs`).
//! - **IPC,** in `direct` mode only: configd (`.configd` for NAT64
//!   discovery's dynamic store, `.DNSConfiguration` for the resolver's
//!   servers) and mDNSResponder's socket, which resolves names. Nothing in
//!   `socks5` or offline mode, where neither runs.
//! - **Network:** `direct`, any outbound address and a local UDP bind;
//!   `socks5`, TCP to the proxy's port, at `localhost` where the proxy is on
//!   loopback, or on any host (the compiler refuses an address literal);
//!   offline, none.
//!
//! Only operations macOS 12 already knows, the oldest the browser runs on
//! (Electron's own minimum).

use std::path::{Path, PathBuf};

use super::Network;

/// A grant's paths, canonical, as `confine` resolves them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grants {
    /// Read and written.
    pub read_write: Vec<PathBuf>,
    /// Directories only read, and everything beneath them.
    pub read_only_dirs: Vec<PathBuf>,
    /// Files only read.
    pub read_only_files: Vec<PathBuf>,
}

/// A profile and the parameters it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub text: String,
    /// `(name, value)` for each `(param "name")`.
    pub params: Vec<(String, String)>,
}

/// What the system's own code reads: libraries, frameworks and dyld's
/// shared cache (which macOS 13 and later keep in a cryptex), and the
/// devices every process opens.
const SYSTEM_READ: &str = r#"(allow file-read*
    (subpath "/usr/lib")
    (subpath "/System/Library")
    (subpath "/System/Cryptexes")
    (subpath "/System/Volumes/Preboot/Cryptexes")
    (subpath "/private/var/db/dyld")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom"))
(allow file-write-data (literal "/dev/null"))
"#;

/// The sysctls the services read, by name: the CPU (std and tokio's
/// parallelism, the crypto crates' feature detection) and the OS's
/// version. After Chromium's `common.sb`.
pub const SYSCTLS: &str = r#"(allow sysctl-read
    (sysctl-name "hw.activecpu")
    (sysctl-name "hw.byteorder")
    (sysctl-name "hw.cachelinesize")
    (sysctl-name "hw.cpufamily")
    (sysctl-name "hw.cputype")
    (sysctl-name "hw.cpusubtype")
    (sysctl-name "hw.l1dcachesize")
    (sysctl-name "hw.l1icachesize")
    (sysctl-name "hw.l2cachesize")
    (sysctl-name "hw.l3cachesize")
    (sysctl-name "hw.logicalcpu")
    (sysctl-name "hw.logicalcpu_max")
    (sysctl-name "hw.machine")
    (sysctl-name "hw.memsize")
    (sysctl-name "hw.ncpu")
    (sysctl-name "hw.pagesize")
    (sysctl-name "hw.physicalcpu")
    (sysctl-name "hw.physicalcpu_max")
    (sysctl-name "hw.vectorunit")
    (sysctl-name "kern.hostname")
    (sysctl-name "kern.maxfilesperproc")
    (sysctl-name "kern.osproductversion")
    (sysctl-name "kern.osrelease")
    (sysctl-name "kern.ostype")
    (sysctl-name "kern.osvariant_status")
    (sysctl-name "kern.osversion")
    (sysctl-name "kern.usrstack64")
    (sysctl-name "kern.version")
    (sysctl-name "sysctl.proc_cputype")
    (sysctl-name-prefix "hw.optional.")
    (sysctl-name-prefix "hw.perflevel"))
"#;

/// The routing sysctls `getifaddrs` reads: NAT64 discovery's interface
/// list, in `direct` mode only.
const INTERFACE_SYSCTLS: &str = "(allow sysctl-read (sysctl-name-prefix \"net.route\"))\n";

/// The root symlinks every absolute path the services use may cross.
const ROOT_LINKS: [&str; 4] = ["/", "/etc", "/tmp", "/var"];

/// configd's Mach services and mDNSResponder's socket: the `ipc` property's
/// authorized channels beside main's stdio, in `direct` mode (design 0010,
/// "macOS").
const DIRECT_IPC: &str = r#"(allow mach-lookup
    (global-name "com.apple.SystemConfiguration.configd")
    (global-name "com.apple.SystemConfiguration.DNSConfiguration"))
(allow network-outbound
    (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
"#;

/// The profile for `network`, `refer` and `grants`.
pub fn profile(network: Network, refer: bool, grants: &Grants) -> Result<Profile, String> {
    let mut params = Vec::new();
    let mut param = |prefix: &str, path: &Path| -> Result<String, String> {
        let value = path
            .to_str()
            .ok_or("a grant's path isn't UTF-8")?
            .to_owned();
        // macOS paths, checked as text so the tests run on every OS.
        if value.contains('\0') || !value.starts_with('/') {
            return Err("a grant's path is relative or holds a NUL".into());
        }
        let name = format!(
            "{prefix}_{}",
            params
                .iter()
                .filter(|(n, _): &&(String, String)| n.starts_with(&format!("{prefix}_")))
                .count()
        );
        params.push((name.clone(), value));
        Ok(name)
    };

    let mut text = String::from("(version 1)\n(deny default)\n");
    text.push_str("(allow process-info* (target self))\n");
    text.push_str("(allow signal (target self))\n");
    text.push_str(SYSCTLS);
    text.push_str(SYSTEM_READ);

    // Metadata on each grant's ancestors, so its path resolves; none on
    // anything else.
    let mut ancestors: Vec<PathBuf> = ROOT_LINKS.iter().map(PathBuf::from).collect();
    for path in grants
        .read_write
        .iter()
        .chain(&grants.read_only_dirs)
        .chain(&grants.read_only_files)
    {
        for ancestor in path.ancestors().skip(1) {
            if !ancestors.iter().any(|known| known == ancestor) {
                ancestors.push(ancestor.to_path_buf());
            }
        }
    }
    text.push_str("(allow file-read-metadata");
    for ancestor in &ancestors {
        let name = param("UP", ancestor)?;
        text.push_str(&format!("\n    (literal (param \"{name}\"))"));
    }
    text.push_str(")\n");

    for dir in &grants.read_only_dirs {
        let name = param("RO", dir)?;
        text.push_str(&format!(
            "(allow file-read* (subpath (param \"{name}\")))\n"
        ));
    }
    for file in &grants.read_only_files {
        let name = param("ROF", file)?;
        text.push_str(&format!(
            "(allow file-read* (literal (param \"{name}\")))\n"
        ));
    }
    for dir in &grants.read_write {
        let name = param("RW", dir)?;
        text.push_str(&format!(
            "(allow file-read* file-write-create file-write-data file-write-unlink file-ioctl\n    (subpath (param \"{name}\")))\n"
        ));
        if refer {
            text.push_str(&format!("(allow file-link (subpath (param \"{name}\")))\n"));
        }
    }

    match network {
        Network::Direct => {
            text.push_str(DIRECT_IPC);
            text.push_str(INTERFACE_SYSCTLS);
            text.push_str("(allow network-outbound (remote ip \"*:*\"))\n");
            text.push_str("(allow network-bind (local udp \"*:*\"))\n");
        }
        Network::Socks5 { port, loopback } => {
            let host = if loopback { "localhost" } else { "*" };
            text.push_str(&format!(
                "(allow network-outbound (remote tcp \"{host}:{port}\"))\n"
            ));
        }
        Network::Offline => {}
    }
    Ok(Profile { text, params })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants() -> Grants {
        Grants {
            read_write: vec!["/Users/u/Library/Freedom/ipfs-data/freedom-ipfs".into()],
            read_only_dirs: Vec::new(),
            read_only_files: vec!["/private/var/run/resolv.conf".into()],
        }
    }

    const PERSISTENT_DIRECT: &str = r#"(version 1)
(deny default)
(allow process-info* (target self))
(allow signal (target self))
SYSCTLS(allow file-read*
    (subpath "/usr/lib")
    (subpath "/System/Library")
    (subpath "/System/Cryptexes")
    (subpath "/System/Volumes/Preboot/Cryptexes")
    (subpath "/private/var/db/dyld")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom"))
(allow file-write-data (literal "/dev/null"))
(allow file-read-metadata
    (literal (param "UP_0"))
    (literal (param "UP_1"))
    (literal (param "UP_2"))
    (literal (param "UP_3"))
    (literal (param "UP_4"))
    (literal (param "UP_5"))
    (literal (param "UP_6"))
    (literal (param "UP_7"))
    (literal (param "UP_8"))
    (literal (param "UP_9"))
    (literal (param "UP_10"))
    (literal (param "UP_11")))
(allow file-read* (literal (param "ROF_0")))
(allow file-read* file-write-create file-write-data file-write-unlink file-ioctl
    (subpath (param "RW_0")))
(allow mach-lookup
    (global-name "com.apple.SystemConfiguration.configd")
    (global-name "com.apple.SystemConfiguration.DNSConfiguration"))
(allow network-outbound
    (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
(allow sysctl-read (sysctl-name-prefix "net.route"))
(allow network-outbound (remote ip "*:*"))
(allow network-bind (local udp "*:*"))
"#;

    #[test]
    fn the_persistent_process_in_direct_mode() {
        let profile = profile(Network::Direct, false, &grants()).unwrap();
        assert_eq!(profile.text, PERSISTENT_DIRECT.replace("SYSCTLS", SYSCTLS));
        let value = |name: &str| {
            profile
                .params
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            value("RW_0"),
            Some("/Users/u/Library/Freedom/ipfs-data/freedom-ipfs")
        );
        assert_eq!(value("ROF_0"), Some("/private/var/run/resolv.conf"));
        // The root links first, then each grant's ancestors, once each.
        let ups: Vec<&str> = profile
            .params
            .iter()
            .filter(|(n, _)| n.starts_with("UP_"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            ups,
            [
                "/",
                "/etc",
                "/tmp",
                "/var",
                "/Users/u/Library/Freedom/ipfs-data",
                "/Users/u/Library/Freedom",
                "/Users/u/Library",
                "/Users/u",
                "/Users",
                "/private/var/run",
                "/private/var",
                "/private",
            ]
        );
    }

    #[test]
    fn socks5_names_the_proxy_port_and_its_host_where_it_is_loopback() {
        let loopback = profile(
            Network::Socks5 {
                port: 9150,
                loopback: true,
            },
            false,
            &Grants::default(),
        )
        .unwrap();
        assert!(
            loopback
                .text
                .ends_with("(allow network-outbound (remote tcp \"localhost:9150\"))\n")
        );
        let lan = profile(
            Network::Socks5 {
                port: 9150,
                loopback: false,
            },
            false,
            &Grants::default(),
        )
        .unwrap();
        assert!(
            lan.text
                .ends_with("(allow network-outbound (remote tcp \"*:9150\"))\n")
        );
        // No resolver, no configd, no UDP: neither runs in socks5 mode.
        for text in [&loopback.text, &lan.text] {
            assert!(!text.contains("mach-lookup"));
            assert!(!text.contains("mDNSResponder"));
            assert!(!text.contains("udp"));
            assert_eq!(text.matches("network-").count(), 1);
        }
    }

    #[test]
    fn offline_and_ephemeral_profiles_write_nothing_and_reach_nothing() {
        let offline = profile(Network::Offline, false, &Grants::default()).unwrap();
        assert!(!offline.text.contains("network-"));
        assert!(!offline.text.contains("mach-lookup"));
        // The one write: /dev/null.
        assert_eq!(offline.text.matches("file-write").count(), 1);
        assert!(
            offline
                .text
                .contains("(allow file-write-data (literal \"/dev/null\"))")
        );
    }

    #[test]
    fn refer_adds_hard_links_in_each_read_write_grant_only() {
        let mut both = grants();
        both.read_write.push("/Users/u/.radicle-home".into());
        let text = profile(Network::Direct, true, &both).unwrap().text;
        assert!(text.contains("(allow file-link (subpath (param \"RW_0\")))"));
        assert!(text.contains("(allow file-link (subpath (param \"RW_1\")))"));
        assert_eq!(text.matches("file-link").count(), 2);
        assert!(
            !profile(Network::Direct, false, &both)
                .unwrap()
                .text
                .contains("file-link")
        );
    }

    #[test]
    fn no_metadata_change_is_allowed_anywhere() {
        let text = profile(Network::Direct, true, &grants()).unwrap().text;
        for operation in [
            "file-write-mode",
            "file-write-owner",
            "file-write-flags",
            "file-write-times",
            "file-write-xattr",
            "file-write*",
            "process-exec",
            "process-fork",
            "system.sb",
        ] {
            assert!(!text.contains(operation), "{operation}");
        }
    }

    #[test]
    fn sysctls_are_read_by_name_and_none_about_other_processes() {
        for network in [
            Network::Direct,
            Network::Socks5 {
                port: 9150,
                loopback: true,
            },
            Network::Offline,
        ] {
            let text = profile(network, false, &grants()).unwrap().text;
            // Never unrestricted, never another process's.
            assert!(!text.contains("(allow sysctl-read)"), "{text}");
            assert!(!text.contains("kern.proc"), "{text}");
            assert!(!text.contains("procargs"), "{text}");
            assert!(text.contains("(sysctl-name \"hw.ncpu\")"));
            // The interface list in direct mode alone.
            assert_eq!(
                text.contains("net.route"),
                network == Network::Direct,
                "{network:?}"
            );
        }
    }

    #[test]
    fn paths_go_in_as_parameters_never_as_text() {
        let odd = Grants {
            read_write: vec![PathBuf::from("/Users/u/\"quoted\" (dir)")],
            ..Grants::default()
        };
        let profile = profile(Network::Offline, false, &odd).unwrap();
        assert!(!profile.text.contains("quoted"));
        assert!(
            profile
                .params
                .contains(&("RW_0".to_owned(), "/Users/u/\"quoted\" (dir)".to_owned()))
        );
        let relative = Grants {
            read_write: vec![PathBuf::from("relative/dir")],
            ..Grants::default()
        };
        assert!(super::profile(Network::Offline, false, &relative).is_err());
    }
}
