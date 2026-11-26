//! Fault injection for the integration tests (design 0007, Testing: "test
//! hooks behind a cargo feature"). **Only with the `testhooks` feature, in a
//! debug or test build:** without it every hook is a no-op and no variable
//! is read, and a release build with it doesn't compile.
//!
//! - **Holds** wait until a file exists at `<path>`, for at most 30 s, so
//!   the test decides when held work goes on. A confined process sees the
//!   file only where its confinement grants it: the persistent process's
//!   data directory. The ephemeral process is granted none, so its holds
//!   end only at the 30 s, which suits a hold the test never releases.
//!   - `FREEDOM_IPFSD_TEST_HOLD_TEARDOWN=until:<path>` holds each instance's
//!     teardown: the instance runs an untracked job on its runtime's
//!     blocking pool, as a library's would be (reqwest's `getaddrinfo`),
//!     which waits for the instance to be cancelled, logs `test hook: a
//!     teardown is held`, then waits for the file. Only the join of the
//!     instance's runtime waits for it, so quiescence comes once the file
//!     exists.
//!   - `FREEDOM_IPFSD_TEST_HOLD_START=until:<path>` holds each
//!     `ipfs.start`'s job before its build, before it opens its store.
//!   - `FREEDOM_IPFSD_TEST_HOLD_START=after:<path>` holds each
//!     `ipfs.start`'s job once its build has returned, before it looks at
//!     its fence, and logs `test hook: a start's build has returned` first.
//!     A start the test fences meanwhile has only its teardown left inside
//!     the 5 s bound the fence armed once the file exists.
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
//!
//! Out of memory (design 0010, Tests, "The memory cap"; 0007, Testing):
//! - `FREEDOM_IPFSD_TEST_MEMORY_CAP_HEADROOM=<bytes>` lowers the memory cap
//!   the process confines itself with to that much above the private
//!   writable memory it uses then (`VmData`, what `RLIMIT_DATA` counts), on
//!   Linux. `confinement.memory_cap` reports it as read back. Elsewhere it
//!   changes nothing.
//! - `FREEDOM_IPFSD_TEST_OUT_OF_MEMORY` acts in each `ipfs.start`'s build,
//!   once its store has opened, or in `ipfs.stats`:
//!   - `fill`: a memory store opens with its page cap lifted and its hot
//!     cache off, and is filled with distinct 64 KiB blocks, at most 1 GiB,
//!     before the instance is built, until SQLite can't allocate. It logs
//!     `test hook: filling the store` first, and `test hook: the store never
//!     ran out` if it didn't. A put's error goes where the store's open
//!     error goes.
//!   - `allocate`: one Rust allocation of 1 GiB, which past a lowered cap
//!     aborts the process.
//!   - `open`: the store's open fails with an out-of-memory error, and
//!     `stats`: `ipfs.stats`'s store figures do (`CoreError::OutOfMemory`
//!     in a `StoreError`), as an out-of-memory SQLite reports without its
//!     allocator failing would.
//! - `FREEDOM_IPFSD_TEST_SQLITE_FIRST=1` opens and closes a memory store on
//!   the main thread before `main` installs the out-of-memory hook, so the
//!   hook comes too late and is refused (exit 77).
//!
//! Confinement (design 0010, Tests):
//! - `FREEDOM_IPFSD_TEST_CONFINEMENT_POINT=1` logs, at the confinement
//!   point, the process's thread count and what each descriptor above stderr
//!   is (its `/proc/self/fd` link: a test may log a path).
//! - `FREEDOM_IPFSD_TEST_CANARY=<path>` reads the file once confined, from
//!   the main thread, a runtime worker and a blocking-pool thread, and logs
//!   whether each read it.
//! - `FREEDOM_IPFSD_TEST_EXEC=1` tries to run `/bin/sh` (`cmd.exe` on
//!   Windows) once confined, and logs whether it ran, or the spawn's error.
//! - `FREEDOM_IPFSD_TEST_CONNECT=<port>` tries TCP to `127.0.0.1:<port>`
//!   once confined.
//! - `FREEDOM_IPFSD_TEST_RESOLV_CONF=<path>` reads the process's DNS
//!   configuration from that file, once confined, as `/etc/resolv.conf` is
//!   read (Unix). With `FREEDOM_IPFSD_TEST_DNS_PORT=<port>`, a parsed
//!   file's nameservers are asked on that port, which a resolv.conf can't
//!   name, so a fixture server needs no privileged port; the report still
//!   says what the parse gave.

// The hooks are for debug and test builds only: some take a `direct`
// instance's address table away (FREEDOM_IPFSD_TEST_DIRECT_UNCHECKED), or
// choose who discovery asks (FREEDOM_IPFSD_TEST_NAT64_RESOLVERS), and others
// let a request's own headers hold or panic its work. build.rs refuses the
// feature in any release-profile or optimized build, by Cargo's profile, not
// by `debug_assertions` (CI checks both ways in).

use std::time::Duration;

use freedom_ipfs_gateway::{GatewayCoreRequest, Instance};
use freedom_ipfs_store::{SqliteBlockStore, StoreError, StoreOptions};

#[cfg(feature = "testhooks")]
fn millis(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// How long a hold waits for its file at most.
#[cfg(feature = "testhooks")]
const HOLD_GIVE_UP: Duration = Duration::from_secs(30);

/// A hold variable's file, if its value is `<at>:<path>`.
#[cfg(feature = "testhooks")]
fn hold(name: &str, at: &str) -> Option<std::path::PathBuf> {
    let value = std::env::var(name).ok()?;
    let path = value.strip_prefix(at)?.strip_prefix(':')?;
    Some(std::path::PathBuf::from(path))
}

/// Waits until a file exists at `path`, or [`HOLD_GIVE_UP`] has passed.
#[cfg(feature = "testhooks")]
fn until_released(path: &std::path::Path) {
    let give_up = std::time::Instant::now() + HOLD_GIVE_UP;
    while !path.exists() && std::time::Instant::now() < give_up {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// At the confinement point: logs the thread count and the descriptors
/// above stderr, when asked (`FREEDOM_IPFSD_TEST_CONFINEMENT_POINT`).
pub fn at_confinement_point() {
    #[cfg(all(feature = "testhooks", target_os = "linux"))]
    if std::env::var_os("FREEDOM_IPFSD_TEST_CONFINEMENT_POINT").is_some() {
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

/// Once confined, with the runtime built: the canary, exec and connect
/// probes the variables ask for, each result logged.
pub fn after_confinement(runtime: &tokio::runtime::Handle) {
    #[cfg(feature = "testhooks")]
    {
        use serde_json::json;
        if let Some(canary) = std::env::var_os("FREEDOM_IPFSD_TEST_CANARY") {
            let canary = std::path::PathBuf::from(canary);
            let read = |path: &std::path::Path| std::fs::read(path).is_ok();
            let (sent, results) = std::sync::mpsc::channel();
            sent.send(("main", read(&canary))).ok();
            let (worker, blocking) = (sent.clone(), sent.clone());
            let path = canary.clone();
            drop(runtime.spawn(async move {
                worker.send(("runtime worker", read(&path))).ok();
            }));
            let path = canary.clone();
            drop(runtime.spawn_blocking(move || {
                blocking.send(("blocking pool", read(&path))).ok();
            }));
            drop(sent);
            for _ in 0..3 {
                if let Ok((thread, read)) = results.recv_timeout(Duration::from_secs(10)) {
                    fc_service::log::info("canary", json!({ "thread": thread, "read": read }));
                }
            }
        }
        if std::env::var_os("FREEDOM_IPFSD_TEST_EXEC").is_some() {
            let (program, args) = if cfg!(windows) {
                ("cmd.exe", ["/d", "/c", "exit 0"].as_slice())
            } else {
                ("/bin/sh", ["-c", "exit 0"].as_slice())
            };
            let status = std::process::Command::new(program).args(args).status();
            fc_service::log::info(
                "exec probe",
                json!({
                    "ran": status.is_ok(),
                    "error": status.as_ref().err().and_then(std::io::Error::raw_os_error),
                }),
            );
        }
        if let Some(port) = std::env::var("FREEDOM_IPFSD_TEST_CONNECT")
            .ok()
            .and_then(|port| port.parse::<u16>().ok())
        {
            let connected = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_secs(5),
            )
            .is_ok();
            fc_service::log::info(
                "connect probe",
                json!({ "port": port, "connected": connected }),
            );
        }
    }
    let _ = runtime;
}

/// Holds the instance's teardown, as
/// `FREEDOM_IPFSD_TEST_HOLD_TEARDOWN=until:<path>` says.
#[cfg(feature = "testhooks")]
pub fn hold_teardown(instance: &Instance) {
    let Some(release) = hold("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN", "until") else {
        return;
    };
    let cancelled = instance.context().cancellation_token().clone();
    // Untracked: the runtime's own blocking pool, not a counted region.
    drop(instance.context().handle().spawn_blocking(move || {
        while !cancelled.is_cancelled() {
            std::thread::sleep(Duration::from_millis(10));
        }
        fc_service::log::info("test hook: a teardown is held", serde_json::json!({}));
        until_released(&release);
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

/// The process's DNS configuration from a fixture resolv.conf
/// (`FREEDOM_IPFSD_TEST_RESOLV_CONF`), its parsed nameservers asked on
/// `FREEDOM_IPFSD_TEST_DNS_PORT` when that is set; `None` for the system's.
pub fn dns() -> Option<crate::dns::Dns> {
    #[cfg(all(feature = "testhooks", unix))]
    if let Some(path) = std::env::var_os("FREEDOM_IPFSD_TEST_RESOLV_CONF") {
        use freedom_ipfs_gateway::net::{DnsConfig, DnsSource};
        let parsed = DnsConfig::from_resolv_conf(std::path::Path::new(&path));
        let source = parsed.source().clone();
        let port = std::env::var("FREEDOM_IPFSD_TEST_DNS_PORT")
            .ok()
            .and_then(|port| port.parse::<u16>().ok());
        let config = match port {
            Some(port) if source == DnsSource::System => parsed.with_port(port),
            _ => parsed,
        };
        return Some(crate::dns::Dns { config, source });
    }
    None
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

/// Holds an `ipfs.start`'s job before its build, as
/// `FREEDOM_IPFSD_TEST_HOLD_START=until:<path>` says.
pub fn before_build() {
    #[cfg(feature = "testhooks")]
    if let Some(release) = hold("FREEDOM_IPFSD_TEST_HOLD_START", "until") {
        until_released(&release);
    }
}

/// Holds an `ipfs.start`'s job once its build has returned, before it
/// looks at its fence, as `FREEDOM_IPFSD_TEST_HOLD_START=after:<path>`
/// says.
pub fn at_build_end() {
    #[cfg(feature = "testhooks")]
    if let Some(release) = hold("FREEDOM_IPFSD_TEST_HOLD_START", "after") {
        fc_service::log::info(
            "test hook: a start's build has returned",
            serde_json::json!({}),
        );
        until_released(&release);
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

/// Before `main` installs the out-of-memory hook: SQLite used first, if a
/// test asks (`FREEDOM_IPFSD_TEST_SQLITE_FIRST`), so the hook is refused.
/// On the main thread, which is still the only one: the store opens and
/// closes, and starts no thread.
pub fn sqlite_first() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_IPFSD_TEST_SQLITE_FIRST").is_some()
        && let Ok(store) = SqliteBlockStore::in_memory(1 << 20)
    {
        let _ = store.close(Duration::from_secs(1));
    }
}

/// The process's private writable memory now, in bytes: `VmData` in
/// `/proc/self/status`, what `RLIMIT_DATA` counts.
#[cfg(all(feature = "testhooks", target_os = "linux"))]
fn vm_data() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmData:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

/// The confinement policy, with its memory cap lowered to a headroom above
/// what the process uses now, if a test asks
/// (`FREEDOM_IPFSD_TEST_MEMORY_CAP_HEADROOM`; Linux).
pub fn memory_cap(policy: &mut fc_service::confine::Policy) {
    #[cfg(all(feature = "testhooks", target_os = "linux"))]
    if let Some(headroom) = millis("FREEDOM_IPFSD_TEST_MEMORY_CAP_HEADROOM")
        && let Some(used) = vm_data()
    {
        policy.memory_cap = Some(used.saturating_add(headroom));
    }
    let _ = policy;
}

/// What `FREEDOM_IPFSD_TEST_OUT_OF_MEMORY` asks for, if it is `mode`.
#[cfg(feature = "testhooks")]
fn out_of_memory(mode: &str) -> bool {
    std::env::var("FREEDOM_IPFSD_TEST_OUT_OF_MEMORY").is_ok_and(|wanted| wanted == mode)
}

/// The out-of-memory error the hooks inject: one the store's
/// `is_out_of_memory` recognizes, as an `SQLITE_NOMEM` it reports.
#[cfg(feature = "testhooks")]
fn injected() -> StoreError {
    StoreError::Core(freedom_ipfs_core::CoreError::OutOfMemory(
        "test hook".to_owned(),
    ))
}

/// A memory store's options: `options`, or, for the `fill` hook, its page
/// cap lifted and its hot cache off, so that SQLite's pages hold the
/// blocks' only copies.
pub fn memory_store(options: StoreOptions) -> StoreOptions {
    #[cfg(feature = "testhooks")]
    if out_of_memory("fill") {
        return StoreOptions {
            max_bytes: u64::MAX,
            hot_cache_bytes: Some(0),
            max_page_count: None,
            ..options
        };
    }
    options
}

/// A start's store, once opened: as it is, or filled, or an out-of-memory
/// error, as `FREEDOM_IPFSD_TEST_OUT_OF_MEMORY` asks.
pub fn store_opened(store: SqliteBlockStore) -> Result<SqliteBlockStore, StoreError> {
    #[cfg(feature = "testhooks")]
    {
        /// The fill's blocks, and the most of them: 1 GiB.
        const BLOCK: usize = 64 << 10;
        const MAX_BLOCKS: u64 = 1 << 14;
        if out_of_memory("open") {
            return Err(injected());
        }
        if out_of_memory("allocate") {
            drop(std::hint::black_box(vec![0u8; 1 << 30]));
        }
        if out_of_memory("fill") {
            #[cfg(target_os = "linux")]
            let used = vm_data();
            #[cfg(not(target_os = "linux"))]
            let used: Option<u64> = None;
            fc_service::log::info(
                "test hook: filling the store",
                serde_json::json!({ "vm_data": used }),
            );
            // One buffer for every block, its first bytes making each
            // distinct: the store's own allocations are a few small ones
            // per put, so SQLite's meet the cap first.
            let mut data = vec![0u8; BLOCK];
            for i in 0..MAX_BLOCKS {
                data[..8].copy_from_slice(&i.to_be_bytes());
                let cid = freedom_ipfs_core::cid_from_data(freedom_ipfs_core::CODEC_RAW, &data);
                store.put_block(&cid, &data)?;
            }
            fc_service::log::info("test hook: the store never ran out", serde_json::json!({}));
        }
    }
    Ok(store)
}

/// `ipfs.stats`'s store figures: `figures`, or an out-of-memory error, as
/// `FREEDOM_IPFSD_TEST_OUT_OF_MEMORY=stats` asks.
pub fn store_figures(figures: Result<(u64, u64), StoreError>) -> Result<(u64, u64), StoreError> {
    #[cfg(feature = "testhooks")]
    if out_of_memory("stats") {
        return Err(injected());
    }
    figures
}
