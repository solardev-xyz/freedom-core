//! Out of memory under the memory cap, through the binary (design 0010,
//! Tests, "The memory cap"; 0007, Testing: "The memory cap's fail-stop").
//! Each case is a process of its own, so neither the lowered cap nor the
//! exit reaches the test runner.
//!
//! - **SQLite past the cap** (Linux): with the cap lowered by a test hook to
//!   a few MiB above the process's use, a memory store a test hook fills,
//!   its page cap lifted, ends the process with exit 71. The store's hook
//!   wrote its line, the start that filled it is never answered, and no put
//!   returned.
//! - **Rust past the cap** (Linux): an allocation past it aborts the
//!   process, and the start is never answered.
//! - **An out-of-memory error reaching the service,** as SQLite reports one
//!   its allocator didn't fail (a test hook's): at the store's open, and in
//!   `ipfs.stats`, it ends the process with 71 too, with a static line,
//!   never a reply. At the store's open it does so with the heap exhausted
//!   too (Linux, under a lowered cap): the way out allocates nothing.
//! - **A late hook:** with SQLite used before `main` installs the hook, the
//!   hook is refused, and the process exits 77 before `ipfs.hello`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{Value, json};

/// The hooks' variables (src/testhooks.rs).
const OUT_OF_MEMORY: &str = "FREEDOM_IPFSD_TEST_OUT_OF_MEMORY";
#[cfg(target_os = "linux")]
const HEADROOM: &str = "FREEDOM_IPFSD_TEST_MEMORY_CAP_HEADROOM";

/// The lowered cap's room above what the process uses at its confinement
/// point (a few hundred KiB), 48 MiB: its threads, its runtimes and an
/// instance take some 20 MiB of it, and a fill meets the rest in a few
/// hundred puts.
#[cfg(target_os = "linux")]
const ROOM: &str = "50331648";

/// The log lines of `stderr` with message `msg`.
fn logged(stderr: &str, msg: &str) -> Vec<Value> {
    stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|line| line["msg"] == msg)
        .collect()
}

/// The service's own out-of-memory exits' lines (src/oom.rs), and part of
/// both.
const AT_OPEN: &str = "freedom-ipfsd: out of memory at the store's open; exiting 71\n";
const IN_STATS: &str = "freedom-ipfsd: out of memory in ipfs.stats; exiting 71\n";
const EXITS: &str = "freedom-ipfsd: out of memory";

/// Waits for the process to exit, then checks that no reply to `id` was
/// written, and returns its stderr.
fn unanswered(ipfsd: &mut Ipfsd, id: u64) -> String {
    assert!(ipfsd.stdout_closes_within(EXIT_TIMEOUT));
    let left = ipfsd.leftover();
    assert!(
        left.iter().all(|message| message["id"] != id),
        "a reply to {id}: {left:?}"
    );
    ipfsd.stderr()
}

/// The ephemeral process with its cap lowered, and the out-of-memory hook
/// `mode`. Under `socks5`, so that no NAT64 discovery runs beside the hook
/// and allocates as memory runs out: in these cases nothing else in the
/// process works meanwhile. The proxy is never asked: routing is offline,
/// and the start ends in its build.
/// Whether `stderr` holds Rust's allocation-failure message for `bytes`. The
/// allocator writes it in two pieces, "memory allocation of N" and then
/// " bytes failed", and the service's log writer can land a whole line
/// between them (as on radicled's CI). Only the allocator writes either
/// piece, so the two in order are its message, whatever came between.
#[cfg(target_os = "linux")]
fn allocation_failed(stderr: &str, bytes: u64) -> bool {
    let head = format!("memory allocation of {bytes}");
    stderr
        .find(&head)
        .is_some_and(|at| stderr[at + head.len()..].contains(" bytes failed"))
}

#[cfg(target_os = "linux")]
fn capped(mode: &str, env: &[(&str, &str)]) -> Ipfsd {
    let proxy = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
    let mut env = env.to_vec();
    env.extend([(HEADROOM, ROOM), (OUT_OF_MEMORY, mode)]);
    Ipfsd::ephemeral_on(&socks5(proxy), &env)
}

/// The cap `hello` reports, lowered below 0010's 2 GiB.
#[cfg(target_os = "linux")]
fn lowered_cap(ipfsd: &mut Ipfsd) -> u64 {
    let hello = ipfsd.hello();
    let cap = hello["result"]["confinement"]["memory_cap"]
        .as_u64()
        .unwrap_or_else(|| panic!("no memory cap: {hello}"));
    assert!(cap < 1 << 31, "{hello}");
    cap
}

#[cfg(target_os = "linux")]
#[test]
fn an_sqlite_allocation_past_the_cap_exits_71_and_answers_nothing() {
    // The fill runs in the start's build: its deadline never answers first
    // on a loaded machine.
    let mut ipfsd = capped(
        "fill",
        &[("FREEDOM_IPFSD_TEST_START_DEADLINE_MS", "120000")],
    );
    let cap = lowered_cap(&mut ipfsd);
    let id = ipfsd.request("ipfs.start", memory("e-1"));
    // A few seconds of puts in a debug build: the hang guard, not a bound.
    let status = ipfsd.exit_status(READ_TIMEOUT);
    let stderr = unanswered(&mut ipfsd, id);
    assert_eq!(status.code(), Some(71), "{status}: {stderr}");
    // SQLite's allocator ended it, through the store's hook: its line, and
    // not the service's own exit, which a returned error would reach.
    let line = String::from_utf8_lossy(freedom_ipfs_store::OUT_OF_MEMORY_LINE);
    assert!(stderr.contains(line.as_ref()), "{stderr}");
    assert!(!stderr.contains(EXITS), "{stderr}");
    let filling = logged(&stderr, "test hook: filling the store");
    assert_eq!(filling.len(), 1, "{stderr}");
    let used = filling[0]["vm_data"].as_u64().unwrap();
    assert!(used < cap, "the fill began past the cap: {used} {cap}");
    assert!(
        logged(&stderr, "test hook: the store never ran out").is_empty(),
        "{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_rust_allocation_past_the_cap_aborts_and_answers_nothing() {
    use std::os::unix::process::ExitStatusExt;

    let mut ipfsd = capped("allocate", &[]);
    lowered_cap(&mut ipfsd);
    let id = ipfsd.request("ipfs.start", memory("e-1"));
    let status = ipfsd.exit_status(EXIT_TIMEOUT);
    let stderr = unanswered(&mut ipfsd, id);
    // Rust's allocator: its message, then SIGABRT.
    assert_eq!(status.signal(), Some(6), "{status}: {stderr}");
    assert!(allocation_failed(&stderr, 1 << 30), "{stderr}");
}

#[test]
fn an_out_of_memory_error_at_the_stores_open_exits_71_and_answers_nothing() {
    let mut ipfsd = Ipfsd::ephemeral(&[(OUT_OF_MEMORY, "open")]);
    ipfsd.hello();
    let id = ipfsd.request("ipfs.start", memory("e-1"));
    let code = ipfsd.exit_code(EXIT_TIMEOUT);
    let stderr = unanswered(&mut ipfsd, id);
    assert_eq!(code, Some(71), "{stderr}");
    assert_eq!(stderr.matches(EXITS).count(), 1, "{stderr}");
    assert!(stderr.contains(AT_OPEN), "{stderr}");
    assert!(
        logged(&stderr, "the store won't open").is_empty(),
        "{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn with_the_heap_exhausted_an_out_of_memory_error_still_exits_71() {
    let mut ipfsd = capped("exhaust", &[]);
    lowered_cap(&mut ipfsd);
    let id = ipfsd.request("ipfs.start", memory("e-1"));
    let status = ipfsd.exit_status(READ_TIMEOUT);
    let stderr = unanswered(&mut ipfsd, id);
    // Not Rust's abort: the way out allocated nothing.
    assert_eq!(status.code(), Some(71), "{status}: {stderr}");
    assert!(
        stderr.contains("test hook: the heap is exhausted\n"),
        "{stderr}"
    );
    assert!(stderr.contains(AT_OPEN), "{stderr}");
    assert!(!stderr.contains("memory allocation of"), "{stderr}");
    let line = String::from_utf8_lossy(freedom_ipfs_store::OUT_OF_MEMORY_LINE);
    assert!(!stderr.contains(line.as_ref()), "{stderr}");
}

#[test]
fn an_out_of_memory_error_in_stats_exits_71_and_answers_nothing() {
    let mut ipfsd = Ipfsd::ephemeral(&[(OUT_OF_MEMORY, "stats")]);
    ipfsd.hello();
    let started = ipfsd.start(memory("e-1"));
    assert_eq!(started["result"], json!({ "instance": "e-1" }), "{started}");
    let id = ipfsd.request("ipfs.stats", json!({ "instance": "e-1" }));
    let code = ipfsd.exit_code(EXIT_TIMEOUT);
    let stderr = unanswered(&mut ipfsd, id);
    assert_eq!(code, Some(71), "{stderr}");
    assert_eq!(stderr.matches(EXITS).count(), 1, "{stderr}");
    assert!(stderr.contains(IN_STATS), "{stderr}");
}

#[test]
fn a_hook_refused_as_too_late_exits_77_before_hello() {
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_SQLITE_FIRST", "1")]);
    let code = ipfsd.exit_code(EXIT_TIMEOUT);
    assert!(ipfsd.stdout_closes_within(EXIT_TIMEOUT));
    let left = ipfsd.leftover();
    let stderr = ipfsd.stderr();
    assert_eq!(code, Some(77), "{stderr}");
    assert!(left.is_empty(), "{left:?}");
    let refused = logged(
        &stderr,
        "SQLite's out-of-memory hook is refused: the process ends",
    );
    assert_eq!(refused.len(), 1, "{stderr}");
    assert_eq!(
        refused[0]["reason"],
        freedom_ipfs_store::FailStopError::TooLate.to_string(),
        "{stderr}"
    );
}
