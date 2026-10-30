//! Fault injection for the integration tests. **Only with the `testhooks`
//! feature,** which build.rs refuses outside debug and test builds: without
//! it every hook is a no-op and no variable is read.
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
//! - `FREEDOM_CORED_TEST_COMMIT_HOLD` names a file: after that stall, a job
//!   waits until the file exists or the core begins to exit (at most 120 s).
//!   So a test holds a committed job as long as it needs, or until the
//!   exit drain, without racing the core's clock.
//! - `FREEDOM_CORED_TEST_REFUSED_CLAIM_HOLD` names a file: a job whose claim
//!   was refused waits, before it cleans up, until that file exists (at
//!   most 120 s). It stands for a slow disk under that cleanup, held for as
//!   long as the test needs.
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
//!   (`testmethods`), which make responses of any size. Builds without the
//!   feature don't compile them, nor this hook.
//! - `FREEDOM_CORED_TEST_HOLD_REPLY` names a request ID: its reply, if it
//!   is one valid only under the vault's epoch (`nodes.seal_radicle_key`),
//!   waits in the loop's outbox as if the writer had no room, until the
//!   loop's next frame or room moves it.

use std::time::Duration;

/// Set as the core begins to exit; it releases a held commit.
#[cfg(feature = "testhooks")]
static EXITING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The core is about to wait for committed work and exit.
#[cfg(feature = "testhooks")]
pub fn exiting() {
    EXITING.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Waits until `release` exists, `also` holds, or 120 s pass.
#[cfg(feature = "testhooks")]
fn hold(release: &std::ffi::OsStr, also: impl Fn() -> bool) {
    let until = std::time::Instant::now() + Duration::from_secs(120);
    while !std::path::Path::new(release).exists() && !also() && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(feature = "testhooks")]
fn millis(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

#[cfg(feature = "testhooks")]
pub fn snapshot_delay() {
    if let Some(ms) = millis("FREEDOM_CORED_TEST_SNAPSHOT_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(feature = "testhooks")]
pub fn job_delay() {
    if let Some(ms) = millis("FREEDOM_CORED_TEST_JOB_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(feature = "testhooks")]
pub fn refused_claim_hold() {
    if let Some(release) = std::env::var_os("FREEDOM_CORED_TEST_REFUSED_CLAIM_HOLD") {
        hold(&release, || false);
    }
}

#[cfg(feature = "testhooks")]
pub fn commit_delay() {
    if let Ok(marker) = std::env::var("FREEDOM_CORED_TEST_COMMIT_MARKER") {
        let _ = std::fs::write(marker, b"claimed");
    }
    if let Some(ms) = millis("FREEDOM_CORED_TEST_COMMIT_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
    if let Some(release) = std::env::var_os("FREEDOM_CORED_TEST_COMMIT_HOLD") {
        hold(&release, || {
            EXITING.load(std::sync::atomic::Ordering::SeqCst)
        });
    }
}

#[cfg(feature = "testhooks")]
pub fn kdf_deadline(default: Duration) -> Duration {
    millis("FREEDOM_CORED_TEST_KDF_DEADLINE_MS").map_or(default, Duration::from_millis)
}

#[cfg(feature = "testhooks")]
pub fn stall(default: Duration) -> Duration {
    millis("FREEDOM_CORED_TEST_STALL_MS").map_or(default, Duration::from_millis)
}

#[cfg(feature = "testhooks")]
pub fn chain_bounds(mut bounds: fc_chain::machine::Bounds) -> fc_chain::machine::Bounds {
    if let Some(total) = millis("FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES") {
        bounds.total_bytes = usize::try_from(total).unwrap_or(usize::MAX);
    }
    bounds
}

#[cfg(feature = "testhooks")]
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

#[cfg(feature = "testhooks")]
pub fn naming_reply() {
    naming_mark("reply");
}

#[cfg(feature = "testhooks")]
pub fn naming_drain(frames: usize) {
    naming_mark(&format!("drain {frames}"));
}

#[cfg(feature = "testhooks")]
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

#[cfg(feature = "testhooks")]
pub fn hold_reply(id: u64) -> bool {
    std::env::var("FREEDOM_CORED_TEST_HOLD_REPLY")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        == Some(id)
}

#[cfg(not(feature = "testhooks"))]
pub fn hold_reply(_id: u64) -> bool {
    false
}

#[cfg(feature = "testhooks")]
pub fn test_methods() -> bool {
    std::env::var_os("FREEDOM_CORED_TEST_METHODS").is_some()
}

#[cfg(not(feature = "testhooks"))]
pub fn snapshot_delay() {}

#[cfg(not(feature = "testhooks"))]
pub fn job_delay() {}

#[cfg(not(feature = "testhooks"))]
pub fn commit_delay() {}

#[cfg(not(feature = "testhooks"))]
pub fn refused_claim_hold() {}

#[cfg(not(feature = "testhooks"))]
pub fn exiting() {}

#[cfg(not(feature = "testhooks"))]
pub fn kdf_deadline(default: Duration) -> Duration {
    default
}

#[cfg(not(feature = "testhooks"))]
pub fn stall(default: Duration) -> Duration {
    default
}

#[cfg(not(feature = "testhooks"))]
pub fn swap(_stage: &str, _path: &std::path::Path) {}

#[cfg(not(feature = "testhooks"))]
pub fn naming_reply() {}

#[cfg(not(feature = "testhooks"))]
pub fn naming_drain(_frames: usize) {}

#[cfg(not(feature = "testhooks"))]
pub fn chain_bounds(bounds: fc_chain::machine::Bounds) -> fc_chain::machine::Bounds {
    bounds
}
