//! Fault injection for the integration tests. **Debug builds only:** in
//! release builds every hook is a no-op and no variable is read.
//!
//! - `FREEDOM_CORED_TEST_SNAPSHOT_DELAY_MS` stalls the startup snapshot read.
//! - `FREEDOM_CORED_TEST_JOB_DELAY_MS` stalls each vault job before it does
//!   anything (so before its commit point).
//! - `FREEDOM_CORED_TEST_KDF_DEADLINE_MS` replaces the 30 s KDF deadline.
//! - `FREEDOM_CORED_TEST_STALL_MS` replaces the 30 s the vault loop's
//!   replies may wait on a writer that writes nothing before the core
//!   exits.
//! - `FREEDOM_CORED_TEST_COMMIT_DELAY_MS` stalls a job right after it claims
//!   its commit point, before the rename or unlink.
//! - `FREEDOM_CORED_TEST_COMMIT_MARKER` names a file created the moment a job
//!   claims its commit point (before that stall), so tests can wait for it.
//! - `FREEDOM_CORED_TEST_REFUSED_CLAIM_DELAY_MS` stalls a job whose claim
//!   was refused, before it cleans up: a slow disk under that cleanup.
//! - `FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES` replaces the chain total's
//!   256 MiB (design 0005, Bounds), so a test can bring it near full.
//! - `FREEDOM_CORED_TEST_NAMING_MARKER` names a file the naming thread
//!   appends a line to for each reply it makes (`reply`), and at its end
//!   for the waiting frames it hands to the writer (`drain <count>`), so
//!   tests can wait for both while main isn't reading.
//! - `FREEDOM_CORED_TEST_SWAP` (`<stage>=<path>`) renames the file at
//!   `<path>` over the file the core is about to use at `<stage>`, once (the
//!   rename consumes it): `journal` right after recovery read the journal,
//!   `checked` right after a staged or temp file was checked and before its
//!   identity is compared, `renaming` right before a staged node file is
//!   renamed. It stands for a same-user process winning a race.
//! - `FREEDOM_CORED_TEST_METHODS` enables the `test.*` methods
//!   (`testmethods`), which make responses of any size. Release builds
//!   don't compile them, nor this hook.

use std::time::Duration;

#[cfg(debug_assertions)]
fn millis(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

#[cfg(debug_assertions)]
pub fn snapshot_delay() {
    if let Some(ms) = millis("FREEDOM_CORED_TEST_SNAPSHOT_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(debug_assertions)]
pub fn job_delay() {
    if let Some(ms) = millis("FREEDOM_CORED_TEST_JOB_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(debug_assertions)]
pub fn refused_claim_delay() {
    if let Some(ms) = millis("FREEDOM_CORED_TEST_REFUSED_CLAIM_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(debug_assertions)]
pub fn commit_delay() {
    if let Ok(marker) = std::env::var("FREEDOM_CORED_TEST_COMMIT_MARKER") {
        let _ = std::fs::write(marker, b"claimed");
    }
    if let Some(ms) = millis("FREEDOM_CORED_TEST_COMMIT_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(debug_assertions)]
pub fn kdf_deadline(default: Duration) -> Duration {
    millis("FREEDOM_CORED_TEST_KDF_DEADLINE_MS").map_or(default, Duration::from_millis)
}

#[cfg(debug_assertions)]
pub fn stall(default: Duration) -> Duration {
    millis("FREEDOM_CORED_TEST_STALL_MS").map_or(default, Duration::from_millis)
}

#[cfg(debug_assertions)]
pub fn chain_bounds(mut bounds: fc_chain::machine::Bounds) -> fc_chain::machine::Bounds {
    if let Some(total) = millis("FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES") {
        bounds.total_bytes = usize::try_from(total).unwrap_or(usize::MAX);
    }
    bounds
}

#[cfg(debug_assertions)]
fn naming_mark(line: &str) {
    use std::io::Write as _;
    if let Some(marker) = std::env::var_os("FREEDOM_CORED_TEST_NAMING_MARKER") {
        // One write per line: the test reads the file while this appends.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(marker)
            .and_then(|mut file| file.write_all(format!("{line}\n").as_bytes()));
    }
}

#[cfg(debug_assertions)]
pub fn naming_reply() {
    naming_mark("reply");
}

#[cfg(debug_assertions)]
pub fn naming_drain(frames: usize) {
    naming_mark(&format!("drain {frames}"));
}

#[cfg(debug_assertions)]
pub fn swap(stage: &str, path: &std::path::Path) {
    let Ok(spec) = std::env::var("FREEDOM_CORED_TEST_SWAP") else {
        return;
    };
    if let Some((wanted, replacement)) = spec.split_once('=')
        && wanted == stage
    {
        let _ = std::fs::rename(replacement, path);
    }
}

#[cfg(debug_assertions)]
pub fn test_methods() -> bool {
    std::env::var_os("FREEDOM_CORED_TEST_METHODS").is_some()
}

#[cfg(not(debug_assertions))]
pub fn snapshot_delay() {}

#[cfg(not(debug_assertions))]
pub fn job_delay() {}

#[cfg(not(debug_assertions))]
pub fn commit_delay() {}

#[cfg(not(debug_assertions))]
pub fn refused_claim_delay() {}

#[cfg(not(debug_assertions))]
pub fn kdf_deadline(default: Duration) -> Duration {
    default
}

#[cfg(not(debug_assertions))]
pub fn stall(default: Duration) -> Duration {
    default
}

#[cfg(not(debug_assertions))]
pub fn swap(_stage: &str, _path: &std::path::Path) {}

#[cfg(not(debug_assertions))]
pub fn naming_reply() {}

#[cfg(not(debug_assertions))]
pub fn naming_drain(_frames: usize) {}

#[cfg(not(debug_assertions))]
pub fn chain_bounds(bounds: fc_chain::machine::Bounds) -> fc_chain::machine::Bounds {
    bounds
}
