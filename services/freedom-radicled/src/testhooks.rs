//! Fault injection for the integration tests (design 0008, "Rust tests
//! through the binary, with test hooks behind a feature"). **Only with the
//! `testhooks` feature, in a debug or test build:** without it every hook
//! is a no-op and no variable is read, and a release build with it doesn't
//! compile.
//!
//! - `FREEDOM_RADICLED_TEST_IDENTITY_DEADLINE_MS` replaces the 30 s within
//!   which `rad.identity` must follow `rad.hello`'s reply.
//! - `FREEDOM_RADICLED_TEST_THREADS=1` logs, at the confinement point, how
//!   many threads the process has (`/proc/self/task`), and what each
//!   descriptor above stderr is (its `/proc/self/fd` link: a test may log a
//!   path). Linux only.

#[cfg(all(feature = "testhooks", not(debug_assertions)))]
compile_error!("the `testhooks` feature is for debug and test builds only, never a release build");

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
