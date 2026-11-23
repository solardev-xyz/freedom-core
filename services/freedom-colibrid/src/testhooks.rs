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
//!
//! The confinement tests (`tests/confinement.rs`) read the log lines.

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
