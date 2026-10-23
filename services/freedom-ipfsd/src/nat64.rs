//! NAT64 discovery (design 0007, "Network-specific NAT64 prefixes"): the
//! services' shared discovery ([`fc_nat64`]), published to every `direct`
//! instance's gate through a [`Nat64Handle`].
//!
//! The rounds, the states, the lease and the resolvers per OS are
//! `fc-nat64`'s. What is freedom-ipfsd's: the handle the instances' gates
//! read, the rounds' thread's name, the client name macOS's dynamic store
//! sees, and the test hooks' resolvers (`testhooks::nat64_source`).

use std::sync::Arc;

use freedom_ipfs_gateway::net::Nat64Handle;
use freedom_ipfs_gateway::net::gate::Nat64State;

pub use fc_nat64::{Lease, Source, Timing};

/// The rounds' thread.
const THREAD: &str = "ipfsd-nat64";

/// The name macOS's dynamic store session carries.
const CLIENT: &str = "freedom-ipfsd";

/// The process's discovery: the state every `direct` instance's gate reads.
#[derive(Clone)]
pub struct Discovery {
    inner: fc_nat64::Discovery,
    /// The state as published.
    handle: Nat64Handle,
}

impl Discovery {
    /// Discovery over `source`'s resolvers, pending until a lease starts it.
    pub fn new(source: Source, timing: Timing) -> Discovery {
        let (publisher, handle) = Nat64Handle::channel(Nat64State::Pending);
        let host = fc_nat64::Host {
            thread: THREAD,
            publish: Arc::new(move |state: &Nat64State| publisher.publish(state.clone())),
        };
        Discovery {
            inner: fc_nat64::Discovery::new(source, timing, host),
            handle,
        }
    }

    /// Discovery over no resolver, for tests: known, with no prefix, once
    /// a lease starts it.
    #[cfg(test)]
    pub fn none() -> Discovery {
        Discovery::new(Arc::new(Vec::new), Timing::DESIGN)
    }

    /// The OS's resolvers ([`fc_nat64::resolvers::learned`]).
    pub fn os_source() -> Source {
        fc_nat64::Discovery::os_source(CLIENT)
    }

    /// A handle on the state, for an instance's policy.
    pub fn handle(&self) -> Nat64Handle {
        self.handle.clone()
    }

    /// What `ipfs.stats` reports of it: the state's name, the prefixes
    /// learned (`addr/len`), and why the last round's resolvers failed,
    /// each a fixed name (never an address).
    pub fn stats(&self) -> serde_json::Value {
        self.inner.stats()
    }

    /// Holds discovery running until the lease is dropped. The first lease
    /// starts it, and one after a pause resumes it, pending again.
    pub fn lease(&self) -> Lease {
        self.inner.lease()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handle the gates read is the state discovery publishes.
    #[test]
    fn the_handle_follows_what_discovery_publishes() {
        let discovery = Discovery::none();
        let handle = discovery.handle();
        assert_eq!(handle.current(), Nat64State::Pending);
        let _lease = discovery.lease();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while handle.current() == Nat64State::Pending && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // No resolver: known, with no prefix.
        assert_eq!(handle.current(), Nat64State::known([]));
        assert_eq!(discovery.stats()["state"], "known");
    }
}
