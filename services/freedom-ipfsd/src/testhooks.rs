//! Fault injection for the integration tests (design 0007, Testing: "test
//! hooks behind a cargo feature"). **Only with the `testhooks` feature:**
//! without it every hook is a no-op and no variable is read.
//!
//! - `FREEDOM_IPFSD_TEST_HOLD_TEARDOWN_MS` holds each instance's teardown:
//!   the instance runs an untracked job on its runtime's blocking pool, as
//!   a library's would be (reqwest's `getaddrinfo`), which waits for the
//!   instance to be cancelled and then sleeps this long. Only the join of
//!   the instance's runtime waits for it, so quiescence comes that much
//!   later.
//! - `FREEDOM_IPFSD_TEST_START_DELAY_MS` stalls each `ipfs.start` before it
//!   opens its store.
//! - `FREEDOM_IPFSD_TEST_START_DEADLINE_MS` replaces `ipfs.start`'s 10 s
//!   deadline.
//! - `FREEDOM_IPFSD_TEST_PANIC=start` panics in each `ipfs.start`'s job,
//!   with a payload that names a path, as a fault in the service's own work
//!   would.
//! - `FREEDOM_IPFSD_TEST_REQUEST_HOOKS=1` lets an `ipfs.request`'s own
//!   headers ask for a fault in its work, so one process can serve held,
//!   panicking and ordinary requests side by side:
//!   - `x-freedom-test-hold: head` holds the work before it asks the
//!     gateway, and `body` once its head is queued, before its body, until
//!     the work is cancelled (as any await in it is);
//!   - `x-freedom-test-panic: request` panics in the work before it asks
//!     the gateway, and `body` once its head is queued, with a payload that
//!     names a path: as a fault inside freedom-ipfs on a request's task
//!     would.

use std::time::Duration;

use freedom_ipfs_gateway::{GatewayCoreRequest, Instance};

#[cfg(feature = "testhooks")]
fn millis(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// Holds the instance's teardown, as `FREEDOM_IPFSD_TEST_HOLD_TEARDOWN_MS`
/// says.
#[cfg(feature = "testhooks")]
pub fn hold_teardown(instance: &Instance) {
    let Some(ms) = millis("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN_MS") else {
        return;
    };
    let cancelled = instance.context().cancellation_token().clone();
    // Untracked: the runtime's own blocking pool, not a counted region.
    drop(instance.context().handle().spawn_blocking(move || {
        while !cancelled.is_cancelled() {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(ms));
    }));
}

#[cfg(not(feature = "testhooks"))]
pub fn hold_teardown(_instance: &Instance) {}

/// Stalls an `ipfs.start`, as `FREEDOM_IPFSD_TEST_START_DELAY_MS` says.
pub fn start_delay() {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_IPFSD_TEST_START_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// `ipfs.start`'s deadline: `default`, unless a test replaces it.
pub fn start_deadline(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_IPFSD_TEST_START_DEADLINE_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// Where in a request's work a hook acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Before it asks the gateway.
    Request,
    /// Once its head is queued, before its body.
    Body,
}

/// What a request's test headers ask of its work: nothing, without the
/// feature or `FREEDOM_IPFSD_TEST_REQUEST_HOOKS`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestHooks {
    hold: Option<Phase>,
    panic: Option<Phase>,
}

impl RequestHooks {
    /// Read from `request`'s headers, once, before its work starts.
    pub fn of(request: &GatewayCoreRequest) -> RequestHooks {
        #[cfg(feature = "testhooks")]
        if std::env::var("FREEDOM_IPFSD_TEST_REQUEST_HOOKS").is_ok_and(|on| on == "1") {
            let phase = |name: &str| match request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
            {
                Some("head" | "request") => Some(Phase::Request),
                Some("body") => Some(Phase::Body),
                _ => None,
            };
            return RequestHooks {
                hold: phase("x-freedom-test-hold"),
                panic: phase("x-freedom-test-panic"),
            };
        }
        let _ = request;
        RequestHooks::default()
    }

    /// Acts at `phase`: holds the work until it is cancelled, or panics.
    pub async fn at(&self, phase: Phase) {
        if self.panic == Some(phase) {
            #[allow(clippy::panic)]
            {
                panic!("test panic in a request: SECRET /ipfs/bafy/home/user/.config/Freedom");
            }
        }
        if self.hold == Some(phase) {
            std::future::pending::<()>().await;
        }
    }
}

/// Panics at `point` if `FREEDOM_IPFSD_TEST_PANIC` names it.
pub fn panic_at(point: &str) {
    #[cfg(feature = "testhooks")]
    if std::env::var("FREEDOM_IPFSD_TEST_PANIC").is_ok_and(|wanted| wanted == point) {
        #[allow(clippy::panic)]
        {
            panic!("test panic at {point}: SECRET /home/user/.config/Freedom/ipfs-data");
        }
    }
    let _ = point;
}
