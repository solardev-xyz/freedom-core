//! NAT64 discovery for `direct` mode (design 0008, "The address policy": "the
//! service learns the network's NAT64 prefixes as 0007 does"): fc-nat64's,
//! as freedom-ipfsd runs it, publishing into the dial gate's state
//! ([`dial::Nat64`]).
//!
//! It runs only while a lease is held: the node's start in `direct` mode
//! holds one for the node's life ([`crate::node`]). Until a round settles,
//! the gate's state is pending, and IPv6 outside the fixed forms waits.

use std::sync::Arc;

pub use fc_nat64::{Lease, Source, Timing};

use crate::dial;

const THREAD: &str = "radicled-nat64";

/// The client name discovery's per-OS resolver listing uses.
const CLIENT: &str = "freedom-radicled";

/// Discovery, and the state it publishes to the gate.
#[derive(Clone)]
pub struct Discovery {
    inner: fc_nat64::Discovery,
    state: dial::Nat64,
}

impl Discovery {
    /// Discovery over `source`'s resolvers, pending until a lease starts it.
    pub fn new(source: Source, timing: Timing) -> Self {
        let state = dial::Nat64::pending();
        let published = state.clone();
        let host = fc_nat64::Host {
            thread: THREAD,
            publish: Arc::new(move |new: &freedom_ipfs_addr::Nat64State| {
                published.publish(new.clone());
            }),
        };
        Self {
            inner: fc_nat64::Discovery::new(source, timing, host),
            state,
        }
    }

    /// The OS's resolvers.
    pub fn os_source() -> Source {
        fc_nat64::Discovery::os_source(CLIENT)
    }

    /// The state, as the gate reads it.
    pub fn state(&self) -> dial::Nat64 {
        self.state.clone()
    }

    /// Discovery runs while a lease is held.
    pub fn lease(&self) -> Lease {
        self.inner.lease()
    }

    /// What `rad.stats` reports of it ([`crate::stats`]): its state, at
    /// most `prefixes` of its prefixes, and the first `failures` of why the
    /// last round's resolvers failed, each list cut as fc-nat64 reads it,
    /// so the work is bounded however many resolvers the OS lists.
    pub fn stats(&self, prefixes: usize, failures: usize) -> serde_json::Value {
        self.inner.stats_bounded(prefixes, failures)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::time::{Duration, Instant};

    use freedom_ipfs_addr::Nat64State;
    use radicle::node::Address;

    use super::*;

    #[test]
    fn the_gate_waits_for_discovery_then_takes_what_it_learned() {
        // No resolver to ask: once a lease starts it, a round settles at
        // once, known, with no prefix.
        let discovery = Discovery::new(Arc::new(Vec::new), Timing::DESIGN);
        let routing = dial::routing(
            &fc_service::network::NetworkPolicy::Direct,
            &[],
            discovery.state(),
        )
        .unwrap();
        let ipv6: std::net::SocketAddr = "[2606:4700:4700::1111]:8776".parse().unwrap();
        let target = Address::from(ipv6);
        assert!(!routing.gate.allows(&target, &ipv6), "pending, it waits");

        let _lease = discovery.lease();
        let until = Instant::now() + Duration::from_secs(10);
        while discovery.inner.state() == Nat64State::Pending {
            assert!(Instant::now() < until, "discovery never settled");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(discovery.inner.state(), Nat64State::NONE);
        assert!(routing.gate.allows(&target, &ipv6), "known, it passes");
        assert_eq!(discovery.stats(16, 16)["state"], "known");
    }

    #[test]
    fn the_os_source_lists_resolvers_without_asking_them() {
        // It reads the OS's resolver configuration, and sends nothing.
        let learned = (Discovery::os_source())();
        assert!(learned.len() <= 64);
    }
}
