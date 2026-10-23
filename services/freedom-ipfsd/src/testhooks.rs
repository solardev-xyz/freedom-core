//! Fault injection for the integration tests (design 0007, Testing: "test
//! hooks behind a cargo feature"). **Only with the `testhooks` feature, in a
//! debug or test build:** without it every hook is a no-op and no variable
//! is read, and a release build with it doesn't compile.
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
//! - `FREEDOM_IPFSD_TEST_MEMORY_BUDGET` replaces the process's memory budget
//!   (bytes), so a test can fill it.
//! - `FREEDOM_IPFSD_TEST_STREAM_MEMORY_WAIT_MS` replaces the 10 s a
//!   stream's next fetch waits for memory.
//! - `FREEDOM_IPFSD_TEST_MEMORY_MARGIN_MS` replaces the 50 ms before a
//!   head's deadline at which a request's wait for memory gives up, still at
//!   most half way to the deadline: a test can leave its `busy` room to be
//!   queued in time on a loaded machine.
//! - `FREEDOM_IPFSD_TEST_HTML_PREFETCH_ASSETS` turns upstream's HTML
//!   prefetch on (off by default, as 0007 keeps it), for that many assets,
//!   one at a time: background work, to fill an instance's background queue.
//! - `FREEDOM_IPFSD_TEST_PROGRESS_COUNTS=1` adds `test_progress` to each
//!   `ipfs.stats` reply, in either process: how many targets and events the
//!   instance's recorder and the process's default recorder hold, so a test
//!   can tell what was recorded, and where, even where `progress` is null.
//! - `FREEDOM_IPFSD_TEST_HANDLED_FILE=<path>` appends each request's ID to
//!   the file once the service has handled it on the reader thread (its
//!   reply queued, or its work started): a test can wait for the reader
//!   without reading stdout.
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

// The hooks are for debug and test builds only: some take a `direct`
// instance's address table away (FREEDOM_IPFSD_TEST_DIRECT_UNCHECKED), or
// choose who discovery asks (FREEDOM_IPFSD_TEST_NAT64_RESOLVERS), and others
// let a request's own headers hold or panic its work. A release build with
// the feature doesn't compile (CI checks it doesn't).
#[cfg(all(feature = "testhooks", not(debug_assertions)))]
compile_error!("the `testhooks` feature is for debug and test builds only, never a release build");

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

/// Records that the service has handled request `id`, if a test asks
/// (`FREEDOM_IPFSD_TEST_HANDLED_FILE`): one line per request.
pub fn handled(id: u64) {
    #[cfg(feature = "testhooks")]
    if let Some(path) = std::env::var_os("FREEDOM_IPFSD_TEST_HANDLED_FILE") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(file, "{id}");
        }
    }
    let _ = id;
}

/// What `instance`'s recorder and the process's default recorder hold, if
/// a test asks (`FREEDOM_IPFSD_TEST_PROGRESS_COUNTS=1`).
pub fn progress_counts(
    instance: &freedom_ipfs_gateway::progress::ProgressRecorder,
) -> Option<serde_json::Value> {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_IPFSD_TEST_PROGRESS_COUNTS").is_some() {
        let counts = |recorder: &freedom_ipfs_gateway::progress::ProgressRecorder| {
            let snapshot = serde_json::to_value(recorder.snapshot()).unwrap_or_default();
            serde_json::json!({ "active_count": snapshot["active_count"],
                "event_count": snapshot["event_count"] })
        };
        let default = freedom_ipfs_gateway::progress::default_recorder();
        return Some(
            serde_json::json!({ "instance": counts(instance), "default": counts(&default) }),
        );
    }
    let _ = instance;
    None
}

/// NAT64 discovery's resolvers: the OS's (`None`), unless a test names its
/// own in `FREEDOM_IPFSD_TEST_NAT64_RESOLVERS`, comma-separated: each a
/// socket address to ask, or anything else, which is a resolver that can't
/// be asked. Empty is none, so discovery knows no prefix at once.
pub fn nat64_source() -> Option<crate::nat64::Source> {
    #[cfg(feature = "testhooks")]
    if let Ok(list) = std::env::var("FREEDOM_IPFSD_TEST_NAT64_RESOLVERS") {
        use fc_nat64::resolvers::Learned;
        let learned: Vec<Learned> = list
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| match item.parse() {
                Ok(addr) => Learned::Ask(addr),
                Err(_) => Learned::Unaskable(item.to_string()),
            })
            .collect();
        return Some(std::sync::Arc::new(move || learned.clone()));
    }
    None
}

/// A `direct` instance's address table: `checked`, unless a test turns it
/// off (`FREEDOM_IPFSD_TEST_DIRECT_UNCHECKED`), for providers on loopback.
pub fn direct_addresses(
    checked: freedom_ipfs_gateway::net::Addresses,
) -> freedom_ipfs_gateway::net::Addresses {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_IPFSD_TEST_DIRECT_UNCHECKED").is_some() {
        return freedom_ipfs_gateway::net::Addresses::Unchecked;
    }
    checked
}

/// The process's memory budget: `default`, unless a test replaces it.
pub fn memory_budget(default: usize) -> usize {
    #[cfg(feature = "testhooks")]
    if let Some(bytes) = millis("FREEDOM_IPFSD_TEST_MEMORY_BUDGET") {
        return usize::try_from(bytes).unwrap_or(default);
    }
    default
}

/// How long a stream's next fetch waits for memory: `default`, unless a
/// test replaces it.
pub fn stream_memory_wait(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_IPFSD_TEST_STREAM_MEMORY_WAIT_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// How long before a head's deadline a request's wait for memory gives
/// up: `default`, unless a test replaces it.
pub fn memory_margin(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_IPFSD_TEST_MEMORY_MARGIN_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// The instance's gateway configuration, with HTML prefetch on if a test
/// asks for it.
pub fn gateway_config(
    config: freedom_ipfs_gateway::GatewayConfig,
) -> freedom_ipfs_gateway::GatewayConfig {
    #[cfg(feature = "testhooks")]
    if let Some(assets) = millis("FREEDOM_IPFSD_TEST_HTML_PREFETCH_ASSETS") {
        let assets = usize::try_from(assets).unwrap_or(0);
        return config.with_html_prefetch(freedom_ipfs_gateway::GatewayHtmlPrefetchConfig::new(
            assets,
            64 << 10,
            1,
        ));
    }
    config
}

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
