//! Test hooks (the `testhooks` feature, which `build.rs` refuses outside
//! debug and test builds). Without the feature, none exist.
//!
//! - `test_clock_ms` in `colibri.request` sets the C core's clock for a
//!   replay ([`crate::request`]).
//! - `FREEDOM_COLIBRID_TEST_CANARY=<path>`: once confined, the process
//!   reads the file, from the main thread and from the verifier thread, and
//!   logs `test canary` with the thread and whether it could.
//! - `FREEDOM_COLIBRID_TEST_WRITE=<path>`: the same with a write
//!   (`test write`).
//! - `FREEDOM_COLIBRID_TEST_SOCKET=1`: the same with a UDP socket bound to
//!   loopback (`test socket`).
//! - `FREEDOM_COLIBRID_TEST_STEP=crash`: inside a request's step, behind
//!   its marker, the process aborts; `=spin`: the step never returns;
//!   `=sleep:<ms>`: the step takes that long first.
//! - `FREEDOM_COLIBRID_TEST_CLASSIFY`: the same inside a request's
//!   classification, its first call into the C core;
//!   `FREEDOM_COLIBRID_TEST_CREATE`: inside a context's or a checkpoint
//!   verifier's creation.
//! - `FREEDOM_COLIBRID_TEST_ANSWER=crash:<n>`: the process aborts inside
//!   the n-th answer it gives the C core.
//! - Each step marker names its call (`"call": "execute"`, and so on).
//! - `FREEDOM_COLIBRID_TEST_MEMORY_BUDGET=<bytes>` replaces the resident
//!   memory budget, so a test can make the process recycle;
//!   `FREEDOM_COLIBRID_TEST_FETCH_BUDGET=<n>` the per-request fetch budget.
//!
//! The confinement tests (`tests/confinement.rs`) read the log lines; the
//! fault tests (`tests/faults.rs`) watch the markers and the exit.

/// Runs the probes the environment asks for, on `thread`.
#[cfg(feature = "testhooks")]
pub fn probe(thread: &str) {
    use fc_service::log;
    use serde_json::json;

    if let Some(path) = std::env::var_os("FREEDOM_COLIBRID_TEST_CANARY") {
        let ok = std::fs::read(&path).is_ok();
        log::info("test canary", json!({ "thread": thread, "ok": ok }));
    }
    if let Some(path) = std::env::var_os("FREEDOM_COLIBRID_TEST_WRITE") {
        let ok = std::fs::write(&path, b"written while confined").is_ok();
        log::info("test write", json!({ "thread": thread, "ok": ok }));
    }
    if std::env::var_os("FREEDOM_COLIBRID_TEST_SOCKET").is_some() {
        let ok = std::net::UdpSocket::bind("127.0.0.1:0").is_ok();
        log::info("test socket", json!({ "thread": thread, "ok": ok }));
    }
}

#[cfg(not(feature = "testhooks"))]
pub fn probe(_thread: &str) {}

/// Inside a request's step, behind its marker: a crash or a spin when the
/// environment asks for one.
pub fn in_step() {
    fault("FREEDOM_COLIBRID_TEST_STEP");
}

/// Inside a request's classification, behind its marker: the same, asked
/// for by `FREEDOM_COLIBRID_TEST_CLASSIFY`.
pub fn in_classify() {
    fault("FREEDOM_COLIBRID_TEST_CLASSIFY");
}

/// Inside a context's or a verifier's creation, behind its marker: the
/// same, asked for by `FREEDOM_COLIBRID_TEST_CREATE`.
pub fn in_create() {
    fault("FREEDOM_COLIBRID_TEST_CREATE");
}

/// Inside an answer given to the C core, behind its marker:
/// `FREEDOM_COLIBRID_TEST_ANSWER=crash:<n>` aborts in the process's n-th.
pub fn in_answer() {
    #[cfg(feature = "testhooks")]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static ANSWERS: AtomicU64 = AtomicU64::new(0);
        let nth = ANSWERS.fetch_add(1, Ordering::Relaxed) + 1;
        let crash_at = std::env::var("FREEDOM_COLIBRID_TEST_ANSWER")
            .ok()
            .and_then(|value| value.strip_prefix("crash:")?.parse::<u64>().ok());
        if crash_at == Some(nth) {
            std::process::abort();
        }
    }
}

#[cfg(feature = "testhooks")]
fn fault(var: &str) {
    match std::env::var(var).as_deref() {
        Ok("crash") => std::process::abort(),
        Ok("spin") => loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        },
        Ok(other) => {
            if let Some(ms) = other.strip_prefix("sleep:").and_then(|ms| ms.parse().ok()) {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        Err(_) => {}
    }
}

#[cfg(not(feature = "testhooks"))]
fn fault(_var: &str) {}

/// The per-request fetch budget a test sets, if any
/// (`FREEDOM_COLIBRID_TEST_FETCH_BUDGET=<n>`).
#[cfg(feature = "testhooks")]
pub fn fetch_budget() -> Option<u32> {
    std::env::var("FREEDOM_COLIBRID_TEST_FETCH_BUDGET")
        .ok()?
        .parse()
        .ok()
}

#[cfg(not(feature = "testhooks"))]
pub fn fetch_budget() -> Option<u32> {
    None
}

/// The resident memory budget a test sets, if any.
#[cfg(feature = "testhooks")]
pub fn memory_budget() -> Option<u64> {
    std::env::var("FREEDOM_COLIBRID_TEST_MEMORY_BUDGET")
        .ok()?
        .parse()
        .ok()
}

#[cfg(not(feature = "testhooks"))]
pub fn memory_budget() -> Option<u64> {
    None
}
