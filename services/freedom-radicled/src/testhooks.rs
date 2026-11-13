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
//!   never return, once its watchdog is armed: a unit that hangs. With
//!   `FREEDOM_RADICLED_TEST_HANG_LIMIT_MS`, units of that kind alone get that
//!   limit; every other unit keeps its own (30 s, or the one above). So a
//!   test can end the hung unit quickly while every unit before it, however
//!   much a slow runner's disk slows its fsyncs, still returns within its
//!   limit: the bound that fires is the hung unit's.
//! - `FREEDOM_RADICLED_TEST_THREADS=1` logs, at the confinement point, how
//!   many threads the process has (`/proc/self/task`), and what each
//!   descriptor above stderr is (its `/proc/self/fd` link: a test may log a
//!   path). Linux only.
//! - `FREEDOM_RADICLED_TEST_OBJECT_CACHE=1` logs, once libgit2's object
//!   cache should be off, whether it keeps what a repository loads
//!   (`libgit2's object cache`, with `on`: [`crate::reads::object_cache_on`]).
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
//! - `FREEDOM_RADICLED_TEST_HOLD_LOOK=<ms>` holds each of the node's
//!   watch's looks at its peers that many milliseconds, with the node held
//!   shared, before it asks heartwood ([`crate::node`]), logging `test
//!   hook: the watch's look holds the node`: a look the stop meets.
//! - `FREEDOM_RADICLED_TEST_WEDGE_REACTOR=<path>` wedges the node's
//!   reactor (#340): while a file exists at `<path>`, each ask of the
//!   node's dial gate, which heartwood makes on its reactor's thread before
//!   a dial, holds that thread until the file is gone, or for 60 s, then
//!   goes on as the gate would ([`routing`]), each hold logging `test hook:
//!   the gate holds the reactor`. Arming it once the node runs leaves the
//!   start alone; a dial then wedges it (`rad.connect_seeds` of a seed).
//! - `FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS` replaces the read pool's and
//!   the write queue's 60 s deadlines. With
//!   `FREEDOM_RADICLED_TEST_WORK_DEADLINE_FROM=<path>` it replaces them
//!   only for the requests admitted once a file exists at `<path>`, so that
//!   a test's setup isn't timed by the deadline it tests.
//! - `FREEDOM_RADICLED_TEST_BUDGET=<bytes>` replaces the output budget's
//!   256 MiB. A reservation that has to wait for it logs `test hook: a
//!   reservation waits for the budget` as it first waits, with the
//!   budget's lock held ([`crate::output`]): a request sent once the line
//!   is logged reserves after it.
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
//!   service's own `HOME`); with `panic`, it panics there. With
//!   `after:<path>` it lets the call run, however long it takes, and holds
//!   the write once the call has returned, before its outcome is marked
//!   and answered, logging `test hook: libradicle's call has returned`,
//!   until a file exists at `<path>` or for 30 s. Once the call has
//!   returned and the write's outcome is marked and answered, it logs
//!   `test hook: the write has returned`, so that a test waits for the
//!   write's end instead of guessing how long a write takes.
//! - `FREEDOM_RADICLED_TEST_HOLD_READ=until:<path>` holds two reads where
//!   `rad.unseed` meets them (#338), until a file exists at `<path>` or for
//!   30 s, logging `test hook: the read holds` with its `op`: `node_info`
//!   between its steps, once the listing's identity check has returned and
//!   before the listing ([`crate::reads`]), and `repo_info` inside its
//!   step, with the node held shared, before libradicle's call. While it is
//!   set, `rad.unseed` logs `test hook: the unseed waits for the node` just
//!   before it waits to hold the node exclusively ([`crate::writes`]).
//! - `FREEDOM_RADICLED_TEST_HOLD_REPAIR` holds each turn of an online
//!   repair, with the node held shared, just before its unit, whatever the
//!   stop, as a slow unit holds the writer ([`crate::repair`]): with a
//!   number, that many milliseconds; with `until:<path>`, until a file
//!   exists at `<path>` or for 30 s. Each logs `test hook: a repair turn
//!   holds the node`. Once the writer has recorded the repair's end, done
//!   or abandoned, so that the repository's COB reads no longer count it
//!   ([`crate::pools`]), it logs `test hook: the repair's end is recorded`:
//!   `an online repair is done` comes a moment before, from the repair's
//!   last turn, so a COB read sent on that line alone can still be
//!   `stopped`. `0` holds nothing, for this line alone.
//! - `FREEDOM_RADICLED_TEST_NETWORK_SLACK_MS` replaces the 30 s a network
//!   operation's deadline adds to its `timeout_ms` ([`crate::network`]).
//! - `FREEDOM_RADICLED_TEST_CLONE=<JSON>` replaces libradicle's clone, past
//!   the clone's start, by a scripted one that reaches no one
//!   ([`scripted_clone`]): `{ "failures": N, "reason": "…", "repeat": R,
//!   "then": "ok" | "fail" | "hold" | "deaf" | "until", "hold_ms": M,
//!   "release": "<path>" }`. It emits `resolving` for N + 1 candidates, and
//!   for each of the N `connecting`, `fetching` and `peer-failed` with the
//!   reason repeated R times (1 by default), as fast as it can, looking at
//!   its token before each candidate as libradicle does; it logs `test
//!   hook: the clone has emitted its failures`. Then `ok` emits the last
//!   candidate's `connecting` and `fetching` and succeeds, and `fail` fails
//!   as libradicle's `FetchFailed` with the reason. `hold` waits for its
//!   token, at most 30 s. `deaf` waits M milliseconds, and `until` until a
//!   file exists at the path or 30 s, whatever the token: each then emits
//!   the last candidate's `connecting` and `fetching`, and is cancelled if
//!   its token is, else succeeds. The three log `test hook: the clone
//!   holds` as they begin. The terminal event follows as libradicle's
//!   `clone_repo_with` emits it, and once the clone has answered it logs
//!   `test hook: the clone has answered`.
//! - `FREEDOM_RADICLED_TEST_IMPORT_LIMIT_MS` replaces the import process's
//!   300 s for `rad.import_repo` from its admission ([`crate::import`]).
//! - `FREEDOM_RADICLED_TEST_HOLD_IMPORT=<stage>@<hold>` holds the import at
//!   `<stage>`: `admitted`, on its thread before the roots are found again
//!   and libradicle's checks and the start; `verified`, once the roots are
//!   found again and match, just before libradicle opens the working copy;
//!   `start`, just past its start, before libradicle's call; or
//!   `created`, `fetched`, `signed`, `seeded` or `moved` (the repository in
//!   place, before the storage directory's flush), each once libradicle has
//!   done that durable step. `<hold>` is a number of milliseconds,
//!   `until:<path>` (until a file exists there, or 30 s), or `panic`. While
//!   it is set, each stage reached logs `test hook: the import reached a
//!   stage`, and the held one `test hook: the import holds at a stage`,
//!   each with its `stage`.
//! - `FREEDOM_RADICLED_TEST_HOLD_CONFINE=until:<path>` holds the process
//!   at its confinement point, after the import's roots are found and
//!   checked and before the rules, until a file exists at `<path>` or for
//!   30 s, logging `test hook: the confinement point holds`: still the one
//!   thread, opening nothing, so a test can change the source there.
//! - `FREEDOM_RADICLED_TEST_HOLD_END=until:<path>` holds the import
//!   process's end, once it has closed an import not yet started to any
//!   start, until a file exists at `<path>` or for 4 s (within the
//!   connection's 5 s exit), logging `test hook: the end holds`: the
//!   process lives on while the import's thread meets the closed start.
//! - `FREEDOM_RADICLED_TEST_PROBE_READ=<path>`,
//!   `FREEDOM_RADICLED_TEST_PROBE_DIAL=<ip:port>` and, on Unix,
//!   `FREEDOM_RADICLED_TEST_PROBE_UNIX=<path>`: once `rad.import_repo` is
//!   admitted, confined, the import's thread reads the file, connects over
//!   TCP, or connects to the Unix socket, and logs `test hook: probe` with
//!   what it tried and whether it worked (`ok`, else the error's kind), so
//!   that a test shows what confinement refuses.
//! - With `FREEDOM_RADICLED_TEST_HOLD_WRITE` or
//!   `FREEDOM_RADICLED_TEST_HOLD_REPAIR` set, the stop logs `test hook: the
//!   stop has fenced the pools` once every pool is fenced, before their
//!   drain ([`crate::pools`]): a test that releases held work only then
//!   knows the stop met it.
//!
//! **One hold on the node per thread** ([`Holding`]): in a build with the
//! feature, a thread that takes the node through `crate::node::Handle`
//! while it holds it panics, before it waits for the lock. Such a second
//! hold deadlocks once `rad.unseed` waits between the two (#338,
//! [`crate::node`]); this finds it in any test that runs the step, with no
//! writer to meet it.
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

/// The time limit of a repair unit of `kind`, whose units otherwise get
/// `limit`: the hung kind's own, if asked.
pub fn unit_limit_of(kind: &str, limit: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if std::env::var("FREEDOM_RADICLED_TEST_HANG_UNIT").is_ok_and(|hang| hang == kind)
        && let Some(ms) = millis("FREEDOM_RADICLED_TEST_HANG_LIMIT_MS")
    {
        return Duration::from_millis(ms);
    }
    #[cfg(not(feature = "testhooks"))]
    let _ = kind;
    limit
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

/// At the confinement point: holds the process there, single-threaded and
/// opening nothing, if asked; then logs the process's thread count when
/// asked.
pub fn at_confinement_point() {
    #[cfg(feature = "testhooks")]
    if let Some(release) = std::env::var("FREEDOM_RADICLED_TEST_HOLD_CONFINE")
        .ok()
        .and_then(|hold| hold.strip_prefix("until:").map(str::to_owned))
    {
        fc_service::log::info(
            "test hook: the confinement point holds",
            serde_json::json!({}),
        );
        until_released(&release);
    }
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

/// Once libgit2's object cache should be off: logs whether it is, when
/// asked.
pub fn object_cache() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_OBJECT_CACHE").is_some() {
        let on = crate::reads::object_cache_on().map_err(|e| e.to_string());
        fc_service::log::info(
            "libgit2's object cache",
            serde_json::json!({ "on": on.as_ref().ok(), "error": on.as_ref().err() }),
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

/// The read pool's and the write queue's deadline, for a request admitted
/// now.
pub fn work_deadline(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS")
        && std::env::var_os("FREEDOM_RADICLED_TEST_WORK_DEADLINE_FROM")
            .is_none_or(|from| std::path::Path::new(&from).exists())
    {
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

/// Holds the calling thread until a file exists at `release`, or for 30 s.
#[cfg(feature = "testhooks")]
fn until_released(release: &str) {
    let until = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < until && !std::path::Path::new(release).exists() {
        std::thread::sleep(Duration::from_millis(5));
    }
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
            until_released(release);
        } else if let Ok(ms) = hold.parse() {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
}

/// Once a write's libradicle call has returned, before its outcome is
/// marked and answered: holds it, if asked (`after:<path>`).
pub fn at_write_call_end() {
    #[cfg(feature = "testhooks")]
    if let Ok(hold) = std::env::var("FREEDOM_RADICLED_TEST_HOLD_WRITE")
        && let Some(release) = hold.strip_prefix("after:")
    {
        fc_service::log::info(
            "test hook: libradicle's call has returned",
            serde_json::json!({}),
        );
        until_released(release);
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

#[cfg(feature = "testhooks")]
thread_local! {
    /// Whether this thread holds the node through `crate::node::Handle`.
    static HOLDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A thread's hold on the node through `crate::node::Handle`, taken
/// before its lock is waited for and let go of with it (see the module's
/// doc). Without the feature it counts nothing.
pub struct Holding(());

impl Holding {
    /// The calling thread's hold. With the feature, a thread that holds
    /// the node already panics here, before it waits for the lock.
    // The panic is how a test finds the second hold, and only with the
    // feature.
    #[allow(clippy::panic)]
    pub fn take() -> Holding {
        #[cfg(feature = "testhooks")]
        if HOLDING.with(|holding| holding.replace(true)) {
            panic!("test hook: a thread took the node while it held it (#338)");
        }
        Holding(())
    }
}

impl Drop for Holding {
    fn drop(&mut self) {
        #[cfg(feature = "testhooks")]
        HOLDING.with(|holding| holding.set(false));
    }
}

/// Where `rad.unseed` meets read `op`: holds it, if asked.
pub fn hold_read(op: &str) {
    #[cfg(feature = "testhooks")]
    if let Ok(hold) = std::env::var("FREEDOM_RADICLED_TEST_HOLD_READ")
        && let Some(release) = hold.strip_prefix("until:")
    {
        fc_service::log::info("test hook: the read holds", serde_json::json!({ "op": op }));
        until_released(release);
    }
    #[cfg(not(feature = "testhooks"))]
    let _ = op;
}

/// Just before `rad.unseed` waits to hold the node exclusively: logs it,
/// if `FREEDOM_RADICLED_TEST_HOLD_READ` is set.
pub fn at_unseed_wait() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_HOLD_READ").is_some() {
        fc_service::log::info(
            "test hook: the unseed waits for the node",
            serde_json::json!({}),
        );
    }
}

/// Before an online repair's unit, with the node held: holds it, if asked.
pub fn hold_repair_turn() {
    #[cfg(feature = "testhooks")]
    if let Ok(hold) = std::env::var("FREEDOM_RADICLED_TEST_HOLD_REPAIR") {
        fc_service::log::info(
            "test hook: a repair turn holds the node",
            serde_json::json!({}),
        );
        if let Some(release) = hold.strip_prefix("until:") {
            until_released(release);
        } else if let Ok(ms) = hold.parse() {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
}

/// Once the writer has recorded an online repair's end, done or
/// abandoned: logs it, if `FREEDOM_RADICLED_TEST_HOLD_REPAIR` is set.
pub fn at_repair_end() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_HOLD_REPAIR").is_some() {
        fc_service::log::info(
            "test hook: the repair's end is recorded",
            serde_json::json!({}),
        );
    }
}

/// As a reservation first waits for the output budget, with its lock
/// held: logs it, if `FREEDOM_RADICLED_TEST_BUDGET` is set.
pub fn at_budget_wait() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_BUDGET").is_some() {
        fc_service::log::info(
            "test hook: a reservation waits for the budget",
            serde_json::json!({}),
        );
    }
}

/// The stop, once every pool is fenced and before their drain: logs it,
/// if `FREEDOM_RADICLED_TEST_HOLD_WRITE` or
/// `FREEDOM_RADICLED_TEST_HOLD_REPAIR` is set.
pub fn at_fence() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_HOLD_WRITE").is_some()
        || std::env::var_os("FREEDOM_RADICLED_TEST_HOLD_REPAIR").is_some()
    {
        fc_service::log::info(
            "test hook: the stop has fenced the pools",
            serde_json::json!({}),
        );
    }
}

/// What a network operation's deadline adds to its `timeout_ms`.
pub fn network_slack(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_NETWORK_SLACK_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// A scripted clone of `rid`, in place of libradicle's, if one is asked
/// for (see the module's doc): its result, its events emitted as
/// libradicle's `clone_repo_with` emits them. `None` otherwise.
pub fn scripted_clone(
    rid: radicle::prelude::RepoId,
    cancel: &libradicle::CancelToken,
    emit: &mut dyn FnMut(libradicle::Progress),
) -> Option<Result<(), libradicle::Error>> {
    #[cfg(feature = "testhooks")]
    if let Ok(spec) = std::env::var("FREEDOM_RADICLED_TEST_CLONE") {
        let result = scripted::run(&spec, rid, cancel, emit);
        emit(match &result {
            Ok(()) => libradicle::Progress::Done,
            Err(libradicle::Error::Cancelled) => libradicle::Progress::Cancelled,
            Err(e) => libradicle::Progress::Failed {
                reason: e.to_string(),
            },
        });
        return Some(result);
    }
    #[cfg(not(feature = "testhooks"))]
    let _ = (rid, cancel, emit);
    None
}

/// A clone's end, once it has answered: logs it, if a scripted clone is
/// asked for.
pub fn at_clone_end() {
    #[cfg(feature = "testhooks")]
    if std::env::var_os("FREEDOM_RADICLED_TEST_CLONE").is_some() {
        fc_service::log::info("test hook: the clone has answered", serde_json::json!({}));
    }
}

#[cfg(feature = "testhooks")]
mod scripted {
    use std::time::{Duration, Instant};

    use libradicle::{CancelToken, Progress};
    use radicle::prelude::RepoId;
    use serde::Deserialize;

    /// The script (see the module's doc).
    #[derive(Deserialize)]
    struct Script {
        failures: usize,
        #[serde(default)]
        reason: String,
        #[serde(default)]
        repeat: Option<usize>,
        then: String,
        #[serde(default)]
        hold_ms: u64,
        #[serde(default)]
        release: Option<String>,
    }

    const NID: &str = "z6MkScriptedSeedScriptedSeedScriptedSeedScripted";

    fn candidate(index: usize, total: usize, emit: &mut dyn FnMut(Progress)) {
        emit(Progress::Connecting {
            nid: NID.to_owned(),
            addr: format!("127.0.0.1:{}", 40000 + index),
            index,
            total,
        });
        emit(Progress::Fetching {
            nid: NID.to_owned(),
            index,
            total,
        });
    }

    pub fn run(
        spec: &str,
        rid: RepoId,
        cancel: &CancelToken,
        emit: &mut dyn FnMut(Progress),
    ) -> Result<(), libradicle::Error> {
        let script: Script = serde_json::from_str(spec)
            .map_err(|e| libradicle::Error::FetchFailed(rid, format!("a bad script: {e}")))?;
        let reason = script.reason.repeat(script.repeat.unwrap_or(1));
        let total = script.failures + 1;
        emit(Progress::Resolving { candidates: total });
        for index in 1..=script.failures {
            if cancel.is_cancelled() {
                return Err(libradicle::Error::Cancelled);
            }
            candidate(index, total, emit);
            emit(Progress::PeerFailed {
                nid: NID.to_owned(),
                index,
                total,
                reason: reason.clone(),
            });
        }
        fc_service::log::info(
            "test hook: the clone has emitted its failures",
            serde_json::json!({}),
        );
        let until = Instant::now() + Duration::from_secs(30);
        let wait = |done: &dyn Fn() -> bool| {
            fc_service::log::info("test hook: the clone holds", serde_json::json!({}));
            while Instant::now() < until && !done() {
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        match script.then.as_str() {
            "ok" => {
                candidate(total, total, emit);
                Ok(())
            }
            "fail" => Err(libradicle::Error::FetchFailed(rid, reason)),
            "hold" => {
                wait(&|| cancel.is_cancelled());
                if cancel.is_cancelled() {
                    Err(libradicle::Error::Cancelled)
                } else {
                    Ok(())
                }
            }
            then => {
                if then == "until" {
                    let release = script.release.unwrap_or_default();
                    wait(&|| std::path::Path::new(&release).exists());
                } else {
                    let held = Instant::now() + Duration::from_millis(script.hold_ms.min(30_000));
                    wait(&|| Instant::now() >= held);
                }
                candidate(total, total, emit);
                if cancel.is_cancelled() {
                    Err(libradicle::Error::Cancelled)
                } else {
                    Ok(())
                }
            }
        }
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

/// In the node's watch's look at its peers, with the node held shared:
/// holds it, if asked.
pub fn hold_look() {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_HOLD_LOOK") {
        fc_service::log::info(
            "test hook: the watch's look holds the node",
            serde_json::json!({}),
        );
        std::thread::sleep(Duration::from_millis(ms));
    }
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

    /// The reactor's wedge (`FREEDOM_RADICLED_TEST_WEDGE_REACTOR`, see the
    /// module's doc): holds the reactor's thread while the file exists, at
    /// most 60 s.
    fn wedge() {
        let Some(armed) = std::env::var_os("FREEDOM_RADICLED_TEST_WEDGE_REACTOR") else {
            return;
        };
        let armed = std::path::Path::new(&armed);
        if !armed.exists() {
            return;
        }
        fc_service::log::info(
            "test hook: the gate holds the reactor",
            serde_json::json!({}),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while std::time::Instant::now() < until && armed.exists() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    impl Gate for LoopbackOnly {
        fn allows(&self, target: &Address, addr: &SocketAddr) -> bool {
            wedge();
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

/// `rad.import_repo`'s time from its admission.
pub fn import_limit(default: Duration) -> Duration {
    #[cfg(feature = "testhooks")]
    if let Some(ms) = millis("FREEDOM_RADICLED_TEST_IMPORT_LIMIT_MS") {
        return Duration::from_millis(ms);
    }
    default
}

/// Once `rad.import_repo` is admitted, on the import's thread: the probes,
/// if asked.
pub fn at_import_admission() {
    #[cfg(feature = "testhooks")]
    {
        let outcome = |result: std::io::Result<()>| match result {
            Ok(()) => "ok".to_owned(),
            Err(e) => e.kind().to_string(),
        };
        if let Some(path) = std::env::var_os("FREEDOM_RADICLED_TEST_PROBE_READ") {
            let read = std::fs::read(&path).map(drop);
            fc_service::log::info(
                "test hook: probe",
                serde_json::json!({ "probe": "read", "outcome": outcome(read) }),
            );
        }
        if let Some(addr) = std::env::var("FREEDOM_RADICLED_TEST_PROBE_DIAL")
            .ok()
            .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        {
            let dial =
                std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map(drop);
            fc_service::log::info(
                "test hook: probe",
                serde_json::json!({ "probe": "dial", "outcome": outcome(dial) }),
            );
        }
        #[cfg(unix)]
        if let Some(path) = std::env::var_os("FREEDOM_RADICLED_TEST_PROBE_UNIX") {
            let unix = std::os::unix::net::UnixStream::connect(path).map(drop);
            fc_service::log::info(
                "test hook: probe",
                serde_json::json!({ "probe": "unix", "outcome": outcome(unix) }),
            );
        }
    }
}

/// At an import's `stage`: logs it, and holds it or panics there, if asked.
// The panic is the fault this hook injects, and only with the feature.
#[allow(clippy::panic)]
pub fn at_import_stage(stage: &str) {
    #[cfg(feature = "testhooks")]
    if let Ok(asked) = std::env::var("FREEDOM_RADICLED_TEST_HOLD_IMPORT") {
        fc_service::log::info(
            "test hook: the import reached a stage",
            serde_json::json!({ "stage": stage }),
        );
        let Some((at, hold)) = asked.split_once('@') else {
            return;
        };
        if at != stage {
            return;
        }
        fc_service::log::info(
            "test hook: the import holds at a stage",
            serde_json::json!({ "stage": stage }),
        );
        if hold == "panic" {
            panic!("test hook: a panic past the import's start");
        }
        if let Some(release) = hold.strip_prefix("until:") {
            until_released(release);
        } else if let Ok(ms) = hold.parse() {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
    #[cfg(not(feature = "testhooks"))]
    let _ = stage;
}

/// The import process's end, once no import can start: holds it, if asked.
pub fn hold_end() {
    #[cfg(feature = "testhooks")]
    if let Some(release) = std::env::var("FREEDOM_RADICLED_TEST_HOLD_END")
        .ok()
        .and_then(|hold| hold.strip_prefix("until:").map(str::to_owned))
    {
        fc_service::log::info("test hook: the end holds", serde_json::json!({}));
        let until = std::time::Instant::now() + Duration::from_secs(4);
        while std::time::Instant::now() < until && !std::path::Path::new(&release).exists() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(all(test, feature = "testhooks"))]
mod tests {
    use super::Holding;

    /// A thread holds the node once: a second hold under the first panics,
    /// before it would wait; one on another thread, or after the first is
    /// let go of, doesn't.
    #[test]
    fn a_thread_holds_the_node_once() {
        let first = Holding::take();
        assert!(std::panic::catch_unwind(Holding::take).is_err());
        assert!(std::thread::spawn(|| drop(Holding::take())).join().is_ok());
        drop(first);
        drop(Holding::take());
    }
}
