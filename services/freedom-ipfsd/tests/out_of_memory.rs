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
//!   `ipfs.stats`, it ends the process with 71 too, never a reply.
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

/// The service's own out-of-memory exit's line.
const EXITS: &str = "out of memory: the process ends";

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
    let mut ipfsd = Ipfsd::ephemeral(&[
        (HEADROOM, ROOM),
        (OUT_OF_MEMORY, "fill"),
        // The fill runs in the start's build: its deadline never answers
        // first on a loaded machine.
        ("FREEDOM_IPFSD_TEST_START_DEADLINE_MS", "120000"),
    ]);
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
    assert!(logged(&stderr, EXITS).is_empty(), "{stderr}");
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

    let mut ipfsd = Ipfsd::ephemeral(&[(HEADROOM, ROOM), (OUT_OF_MEMORY, "allocate")]);
    lowered_cap(&mut ipfsd);
    let id = ipfsd.request("ipfs.start", memory("e-1"));
    let status = ipfsd.exit_status(EXIT_TIMEOUT);
    let stderr = unanswered(&mut ipfsd, id);
    // Rust's allocator: its message, then SIGABRT.
    assert_eq!(status.signal(), Some(6), "{status}: {stderr}");
    assert!(
        stderr.contains("memory allocation of 1073741824 bytes failed"),
        "{stderr}"
    );
}

#[test]
fn an_out_of_memory_error_at_the_stores_open_exits_71_and_answers_nothing() {
    let mut ipfsd = Ipfsd::ephemeral(&[(OUT_OF_MEMORY, "open")]);
    ipfsd.hello();
    let id = ipfsd.request("ipfs.start", memory("e-1"));
    let code = ipfsd.exit_code(EXIT_TIMEOUT);
    let stderr = unanswered(&mut ipfsd, id);
    assert_eq!(code, Some(71), "{stderr}");
    let exits = logged(&stderr, EXITS);
    assert_eq!(exits.len(), 1, "{stderr}");
    assert_eq!(exits[0]["at"], "store_open", "{stderr}");
    assert_eq!(exits[0]["exit"], 71, "{stderr}");
    assert!(
        logged(&stderr, "the store won't open").is_empty(),
        "{stderr}"
    );
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
    let exits = logged(&stderr, EXITS);
    assert_eq!(exits.len(), 1, "{stderr}");
    assert_eq!(exits[0]["at"], "stats", "{stderr}");
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
