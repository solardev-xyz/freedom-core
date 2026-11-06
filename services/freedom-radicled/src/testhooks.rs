//! Fault injection for the integration tests (design 0008, "Rust tests
//! through the binary, with test hooks behind a feature"). **Only with the
//! `testhooks` feature, in a debug or test build:** without it every hook
//! is a no-op and no variable is read, and a release build with it doesn't
//! compile: build.rs refuses the feature in any release-profile or optimized
//! build, by Cargo's profile, not by `debug_assertions`.
//!
//! - `FREEDOM_RADICLED_TEST_IDENTITY_DEADLINE_MS` replaces the 30 s within
//!   which `rad.identity` must follow `rad.hello`'s reply.
//! - `FREEDOM_RADICLED_TEST_RECONCILE_CUTOFF_MS` replaces the 240 s after
//!   `rad.reconcile`'s admission past which no unit starts.
//! - `FREEDOM_RADICLED_TEST_UNIT_LIMIT_MS` replaces a repair unit's 30 s.
//! - `FREEDOM_RADICLED_TEST_HANG_UNIT=<kind>` makes the first repair unit of
//!   that kind (`cache`, `namespace`, … as heartwood's driver names them)
//!   never return, once its watchdog is armed: a unit that hangs.
//! - `FREEDOM_RADICLED_TEST_THREADS=1` logs, at the confinement point, how
//!   many threads the process has (`/proc/self/task`), and what each
//!   descriptor above stderr is (its `/proc/self/fd` link: a test may log a
//!   path). Linux only.
//! - `FREEDOM_RADICLED_TEST_START_DEADLINE_MS` replaces `rad.start`'s 30 s.
//! - `FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS` replaces how long the stop
//!   takes, the pools' drain and then the node's ([`crate::node`]'s 3 s).
//! - `FREEDOM_RADICLED_TEST_STOP_NODE=1` asks the node to stop right after
//!   `rad.start` has answered, behind the stop's back: the node thread ends,
//!   and the node's watch finds it, or the stop does, as a request before
//!   its own (libradicle's `Asked::Earlier`).
//! - `FREEDOM_RADICLED_TEST_HOLD_DOWN=1` holds the node's watch once it has
//!   published `Down`, before it claims exit 70: it logs `test hook: the
//!   watch holds the node down` and never goes on, so only a stop that takes
//!   the `Down` node can end the process with 70.
//! - `FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS` replaces the read pool's and
//!   the write queue's 60 s deadlines.
//! - `FREEDOM_RADICLED_TEST_BUDGET=<bytes>` replaces the output budget's
//!   256 MiB.
//! - `FREEDOM_RADICLED_TEST_HOLD_WORK` holds a pooled method's work, which
//!   this build doesn't serve yet, in its slot before it answers: with `1`
//!   until its token is cancelled (main's cancel, its deadline or the stop),
//!   or for 30 s, and with `deaf` for 30 s whatever its token, as a call
//!   that doesn't check it. Each logs `test hook: work holds its slot`.
//!   `rad.remove_repo`'s, `rad.write`'s and `rad.unseed`'s work is held so
//!   too, with the node held, before its mutation starts ([`crate::quarantine`],
//!   [`crate::writes`]), and `rad.read`'s past its fence, before its build
//!   reserves anything ([`crate::reads`]); `rad.quarantine_list`'s isn't.
//! - `FREEDOM_RADICLED_TEST_HOLD_WRITE` acts on a write just past its
//!   mutation start, before libradicle's call (`rad.write`, `rad.unseed`,
//!   `rad.remove_repo`), logging `test hook: the write has started`: with a
//!   number, it holds it that many milliseconds whatever its token, as a
//!   libradicle call that doesn't check it; with `until:<path>`, it holds
//!   it, whatever its token, until a file exists at `<path>` or for 30 s,
//!   so that the test releases it (a path the confinement grants: in the
//!   service's own `HOME`); with `panic`, it panics there. Once the call
//!   has returned and the write's outcome is marked and answered, it logs
//!   `test hook: the write has returned`, so that a test waits for the
//!   write's end instead of guessing how long a write takes.
//! - `FREEDOM_RADICLED_TEST_HOLD_REPAIR=<ms>` holds each turn of an online
//!   repair that many milliseconds, with the node held shared, just before
//!   its unit, whatever the stop, as a slow unit holds the writer
//!   ([`crate::repair`]). Each logs `test hook: a repair turn holds the
//!   node`.
//!
//! **Hermetic by construction:** a build with the feature never reaches
//! off this host, whatever a test asks of it.
//! - **The node's dial gate** ([`dial_gate`]) holds the service's own gate
//!   to loopback. An address off this host that the service's policy would
//!   let the node dial, or take into its address book, ends the process at
//!   once with a message naming it, before any socket: exit 101, as a
//!   failed test ends. What the policy refuses stays refused. In `direct`
//!   mode no name is resolved at all, so no DNS query leaves: a name is
//!   refused before the system's resolver sees it. In `socks5` mode names
//!   go to the proxy, which must be on loopback, as must its answers to be
//!   let through.
//! - **NAT64 discovery** ([`nat64_source`]) asks only the resolvers a test
//!   names in `FREEDOM_RADICLED_TEST_NAT64_RESOLVERS` (comma-separated
//!   socket addresses, each on loopback; anything else is a resolver that
//!   can't be asked), and none by default.

use std::time::Duration;

#[cfg(feature = "testhooks")]
fn millis(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// How long `rad.identity` may take after `rad.hello`'s reply.
pub fn identity_deadline(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_IDENTITY_DEADLINE_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// How long after `rad.reconcile`'s admission units may start.
pub fn reconcile_cutoff(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_RECONCILE_CUTOFF_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// A repair unit's time limit.
pub fn unit_limit(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_UNIT_LIMIT_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// As a repair unit of `kind` starts, its watchdog armed: hangs, if asked.
pub fn at_unit_start(kind: &str) {
    #[cfg(feature = "testhooks")]
    if std::env::var("FREEDOM_RADICLED_TEST_HANG_UNIT").is_ok_and(|hang| hang == kind) {
        loop {
            std::thread::park();
        }
    }
    #[cfg(not(feature = "testhooks"))]
    let _ = kind;
}

/// At the confinement point: logs the process's thread count when asked.
pub fn at_confinement_point() {
    #[cfg(all(feature = "testhooks", target_os = "linux"))]
    if std::env::var_os("FREEDOM_RADICLED_TEST_THREADS").is_some() {
        let threads = std::fs::read_dir("/proc/self/task").map_or(0, Iterator::count);
        let listing = format!("/proc/{}/fd", std::process::id());
        let descriptors: Vec<String> = std::fs::read_dir("/proc/self/fd")
            .map(|dir| {
                dir.filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_str()
                            .and_then(|name| name.parse::<i32>().ok())
                            .is_some_and(|fd| fd > 2)
                    })
                    .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                    .map(|target| target.to_string_lossy().into_owned())
                    // The listing's own descriptor.
                    .filter(|target| *target != listing)
                    .collect()
            })
            .unwrap_or_default();
        fc_service::log::info(
            "confinement point",
            serde_json::json!({ "threads": threads, "descriptors": descriptors }),
        );
    }
}

/// How long `rad.start` may take.
pub fn start_deadline(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_START_DEADLINE_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// How long the shutdown waits for the node to stop.
pub fn shutdown_within(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// The read pool's and the write queue's deadline.
pub fn work_deadline(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// The output budget's size.
pub fn budget(default: u64) -> u64 {
    #[cfg(feature = "testhooks")]
    if let Some(bytes) = millis("FREEDOM_RADICLED_TEST_BUDGET") {
        return bytes;
    }
    default
}

/// Holds a pooled method's work in its slot, if asked: until `cancel` is
/// cancelled, or whatever it is.
pub fn hold_work(cancel: &libradicle::CancelToken) {
    #[cfg(feature = "testhooks")]
    if let Some(hold) = std::env::var_os("FREEDOM_RADICLED_TEST_HOLD_WORK") {
        let deaf = hold == "deaf";
        fc_service::log::info("test hook: work holds its slot", serde_json::json!({}));
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < until && (deaf || !cancel.is_cancelled()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[cfg(not(feature = "testhooks"))]
    let _ = cancel;
}

/// Just past a write's mutation start: holds it, or panics, if asked.
// The panic is the fault this hook injects, and only with the feature.
#[allow(clippy::panic)]
pub fn at_write_start() {
    #[cfg(feature = "testhooks")]
    if let Ok(hold) = std::env::var("FREEDOM_RADICLED_TEST_HOLD_WRITE") {
        fc_service::log::info("test hook: the write has started", serde_json::json!({}));
        if hold == "panic" {
            panic!("test hook: a panic past the write's start");
        }
        if let Some(release) = hold.strip_prefix("until:") {
            let until = std::time::Instant::now() + Duration::from_secs(30);
            while std::time::Instant::now() < until && !std::path::Path::new(release).exists() {
                std::thread::sleep(Duration::from_millis(5));
            }
        } else if let Ok(ms) = hold.parse() {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
}

/// A write's end, past its start, once its outcome is marked and answered:
/// logs it, if `FREEDOM_RADICLED_TEST_HOLD_WRITE` is set.
pub fn at_write_end() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_HOLD_WRITE").is_some() {
        fc_service::log::info("test hook: the write has returned", serde_json::json!({}));
    }
}

/// Before an online repair's unit, with the node held: holds it, if asked.
pub fn hold_repair_turn() {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_HOLD_REPAIR") {
        fc_service::log::info(
            "test hook: a repair turn holds the node",
            serde_json::json!({}),
        );
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// Whether the node is to be asked to stop right after `rad.start` has
/// answered.
pub fn stop_node() -> bool {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_STOP_NODE").is_some() {
        return true;
    }
    false
}

/// After the node's watch has published `Down`, before it claims the exit:
/// holds it there for good, if asked.
pub fn at_node_down() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_HOLD_DOWN").is_some() {
        fc_service::log::info(
            "test hook: the watch holds the node down",
            serde_json::json!({}),
        );
        loop {
            std::thread::park();
        }
    }
}

/// NAT64 discovery's resolvers: the OS's (`None`), or, with the feature,
/// only those `FREEDOM_RADICLED_TEST_NAT64_RESOLVERS` names, none by
/// default.
pub fn nat64_source() -> Option<crate::nat64::Source> {
    #[cfg(feature = "testhooks")]
    {
        use fc_nat64::resolvers::Learned;
        let list = std::env::var("FREEDOM_RADICLED_TEST_NAT64_RESOLVERS").unwrap_or_default();
        let learned: Vec<Learned> = list
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| match item.parse::<std::net::SocketAddr>() {
                Ok(addr) if addr.ip().to_canonical().is_loopback() => Learned::Ask(addr),
                _ => Learned::Unaskable(item.to_string()),
            })
            .collect();
        Some(std::sync::Arc::new(move || learned.clone()))
    }
    #[cfg(not(feature = "testhooks"))]
    {
        None
    }
}

/// The node's routing: with the feature, its gate held to loopback, and a
/// proxy off this host ends the process (see the module's doc).
pub fn routing(routing: libradicle::Routing) -> libradicle::Routing {
    #[cfg(feature = "testhooks")]
    {
        let mut routing = routing;
        let onion = match routing.onion {
            radicle::node::config::AddressConfig::Proxy { address } => Some(address),
            _ => None,
        };
        for proxy in routing.proxy.iter().chain(onion.iter()) {
            if !proxy.ip().to_canonical().is_loopback() {
                hermetic::off_host(format_args!("the proxy at {proxy}"));
            }
        }
        routing.gate = std::sync::Arc::new(hermetic::LoopbackOnly {
            inner: routing.gate,
            names: routing.proxy.is_some(),
        });
        routing
    }
    #[cfg(not(feature = "testhooks"))]
    routing
}

#[cfg(feature = "testhooks")]
mod hermetic {
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use freedom_ipfs_addr::{Target, classify_host};
    use radicle::node::Address;
    use radicle::node::dial::Gate;

    /// The service's gate, held to loopback.
    #[derive(Debug)]
    pub struct LoopbackOnly {
        pub inner: Arc<dyn Gate>,
        /// Whether names may be resolved: through the proxy, in `socks5`
        /// mode, and never through the system's resolver.
        pub names: bool,
    }

    pub fn off_host(what: std::fmt::Arguments<'_>) -> ! {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "the node tried to reach {what}, off this host: a build with the test hooks \
             reaches loopback only (services/freedom-radicled/src/testhooks.rs)"
        );
        std::process::exit(101)
    }

    fn on_host(addr: &SocketAddr) -> bool {
        addr.ip().to_canonical().is_loopback()
    }

    impl Gate for LoopbackOnly {
        fn allows(&self, target: &Address, addr: &SocketAddr) -> bool {
            let allowed = self.inner.allows(target, addr);
            if allowed && !on_host(addr) {
                off_host(format_args!("{target} at {addr}"));
            }
            allowed
        }

        fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            if !self.names && matches!(classify_host(host), Ok(Target::Name(_))) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the test hooks resolve no name through the system",
                ));
            }
            self.inner.resolve(host, port)
        }

        fn resolve_timeout(&self) -> std::time::Duration {
            self.inner.resolve_timeout()
        }

        fn proxy_resolves_names(&self) -> bool {
            self.inner.proxy_resolves_names()
        }

        fn isolates_streams(&self) -> bool {
            self.inner.isolates_streams()
        }
    }
}
