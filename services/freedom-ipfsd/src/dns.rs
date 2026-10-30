//! The process's one DNS configuration (design 0010, "Name resolution
//! through glibc"; freedom-ipfs #82). In `direct` mode it is read once,
//! confined, before `ipfs.hello`, and every instance's network asks it: the
//! gate's HTTP resolver, libp2p's DNS layer and `/dnsaddr` expansion alike.
//! So the `resolution` the report gives is what every lookup uses.
//! `socks5` reads none: its names go to the proxy.
//!
//! On Unix it is `/etc/resolv.conf` as freedom-ipfs parses it (its first
//! three nameservers, every name looked up as written), or, where that
//! can't be read or parsed, Cloudflare's resolvers, which the report names
//! as the fallback with its reason. It isn't read again: a later change to
//! the file reaches the next process, as a replaced file does under
//! confinement anyway.

use fc_service::confine::{Report, Resolution};
use freedom_ipfs_gateway::net::{DnsConfig, DnsSource};

use crate::network::NetworkPolicy;
use crate::testhooks;

/// The longest `resolution` reason, in bytes: the fallback's cause, as
/// freedom-ipfs gives it, can quote an I/O or parse error.
const MAX_REASON: usize = 256;

/// The process's DNS configuration, and where it came from.
#[derive(Clone, Debug)]
pub struct Dns {
    /// What every `direct` instance's network asks.
    pub config: DnsConfig,
    /// What the report says: the system's configuration, parsed, or the
    /// fallback and why. It is `config.source()`, except under a test hook,
    /// which asks the parsed servers on a fixture's port
    /// ([`testhooks::dns`]).
    pub source: DnsSource,
}

/// The configuration under `network`, read now: in `direct` mode alone.
/// Called once confined, so it reads what the rules let through.
pub fn read(network: &NetworkPolicy) -> Option<Dns> {
    if !matches!(network, NetworkPolicy::Direct) {
        return None;
    }
    Some(testhooks::dns().unwrap_or_else(|| {
        let config = DnsConfig::system();
        let source = config.source().clone();
        Dns { config, source }
    }))
}

/// Adds what resolves names to `report`, on Unix, where the configuration
/// is `/etc/resolv.conf`: `resolv_conf` once it parsed, or `fallback` with
/// the reason. Nothing in `socks5` mode, nor on Windows, which has no
/// resolv.conf and no confinement yet.
pub fn report(report: &mut Report, dns: Option<&Dns>) {
    if !cfg!(unix) {
        return;
    }
    match dns.map(|dns| &dns.source) {
        Some(DnsSource::System) => report.resolution = Some(Resolution::ResolvConf),
        Some(DnsSource::Fallback(why)) => {
            report.resolution = Some(Resolution::Fallback);
            report.reasons.insert(
                "resolution",
                bounded(format!(
                    "{why}; names resolve through the built-in servers (Cloudflare's)"
                )),
            );
        }
        // A configuration a host gives whole: none here.
        _ => {}
    }
}

/// `text`, cut to [`MAX_REASON`] bytes at a character's boundary.
fn bounded(mut text: String) -> String {
    if text.len() > MAX_REASON {
        let mut end = MAX_REASON;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> Report {
        Report {
            mechanism: "none".into(),
            files: fc_service::confine::Status::None,
            exec: fc_service::confine::Status::None,
            ipc: fc_service::confine::Status::None,
            network: fc_service::confine::Status::None,
            gaps: Vec::new(),
            reasons: Default::default(),
            resolution: None,
        }
    }

    #[test]
    fn socks5_reads_no_configuration() {
        let proxy = NetworkPolicy::parse("socks5:127.0.0.1:9050").unwrap();
        assert!(read(&proxy).is_none());
        let mut report = empty();
        super::report(&mut report, None);
        assert_eq!(report.resolution, None);
        assert!(report.reasons.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_report_names_the_configuration_or_the_fallback_and_why() {
        let dir = tempfile::tempdir().unwrap();
        let parsed = dir.path().join("parsed");
        std::fs::write(&parsed, "nameserver 192.0.2.53\n").unwrap();
        let malformed = dir.path().join("malformed");
        std::fs::write(&malformed, "nameserver not-an-address\n").unwrap();
        let missing = dir.path().join("missing");
        let of = |path: &std::path::Path| {
            let config = DnsConfig::from_resolv_conf(path);
            let source = config.source().clone();
            let mut report = empty();
            super::report(&mut report, Some(&Dns { config, source }));
            report
        };

        let report = of(&parsed);
        assert_eq!(report.resolution, Some(Resolution::ResolvConf));
        assert!(report.reasons.is_empty());

        for (path, cause) in [
            (&malformed, "couldn't be parsed"),
            (&missing, "couldn't be read"),
        ] {
            let report = of(path);
            assert_eq!(report.resolution, Some(Resolution::Fallback), "{path:?}");
            let why = &report.reasons["resolution"];
            assert!(
                why.contains(cause) && why.contains("built-in servers"),
                "{why}"
            );
        }
    }

    #[test]
    fn a_long_reason_is_cut_at_a_character() {
        let text = format!("{}é", "x".repeat(MAX_REASON - 1));
        let cut = bounded(text);
        assert_eq!(cut.len(), MAX_REASON - 1);
        assert_eq!(bounded("short".into()), "short");
    }
}
