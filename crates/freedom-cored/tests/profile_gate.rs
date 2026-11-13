//! The latency gate (design 0013, PRF-3): `profile open`'s wall time, timed
//! around the spawn as main times it around `spawnSync`, the binary's first
//! (cold) spawn included.
//!
//! The gate is the optimized binary's, the one main ships: under 100 ms at
//! the 95th percentile on each OS's CI runner. A run that misses is measured
//! once more and judged on that second run, so a runner's stall, which slows
//! one run, doesn't fail it alone, and a slow binary, which slows both, still
//! does. CI's `profile gate` job runs
//! this file alone, `cargo test --release` for each OS's release target and
//! flags, as the Release workflow builds them. A debug build (the
//! workspace's tests) checks only a loose bound on the median: unoptimized
//! code on a shared runner gates nothing, and the median catches a gross
//! regression, which slows every run, but no runner stall, which slows a
//! few.
//!
//! No test hooks: a release build refuses them (build.rs), and `profile
//! open` needs none.
//!
//! What this can't measure: on Windows, an unsigned build's first antivirus
//! scan. GitHub's Windows runners turn real-time scanning off, so 0013
//! qualifies that cost apart, on a machine with it on, before PRF-4.
//!
//! **On Windows the gate reports and doesn't fail, for now** (0013, "The
//! latency gate"): Windows keeps `profile open` in JS until that
//! qualification, so a miss there blocks nothing the browser uses, while the
//! runner's spawns run a p95 over 100 ms in some runs (p50 near 27 ms). The
//! PR that moves Windows's `profile open` to the core sets
//! [`WINDOWS_BLOCKS`], and the gate fails there again.

#![allow(clippy::unwrap_used, clippy::print_stderr)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");

/// Whether a miss fails the gate on Windows: not while Windows keeps
/// `profile open` in JS (see the module's comment).
const WINDOWS_BLOCKS: bool = false;

/// An optimized build, as the release's: the test and the binary come from
/// one Cargo run, so they share its profile.
const OPTIMIZED: bool = !cfg!(debug_assertions);

/// The design's gate, on the optimized binary.
const GATE_P95: Duration = Duration::from_millis(100);

/// A debug build's sanity bound, on the median.
const DEBUG_P50: Duration = Duration::from_secs(1);

/// The opens timed after the catalog's three profiles are registered.
const RUNS: usize = if OPTIMIZED { 100 } else { 20 };

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// `profile open` on the catalog at `app`, timed around the spawn.
fn open(app: &Path, locks: &Path, extra: &[&str]) -> Duration {
    let mut command = Command::new(BIN);
    command
        .args([
            "profile",
            "open",
            "--app-root",
            s(app),
            "--lock-dir",
            s(locks),
        ])
        .args(extra)
        .stdin(Stdio::null());
    let started = Instant::now();
    let out = command.output().unwrap();
    let took = started.elapsed();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    took
}

/// The value at percentile `p` (nearest rank) of sorted `times`.
fn percentile(times: &[Duration], p: usize) -> Duration {
    times[(times.len() * p).div_ceil(100) - 1]
}

#[test]
fn profile_open_is_fast_enough() {
    let root = tempfile::tempdir().unwrap();
    // Resolved on Unix (macOS's temp directory is under a symlink); as it is
    // on Windows, where resolving gives a `\\?\` path main never passes.
    let base = if cfg!(windows) {
        root.path().to_path_buf()
    } else {
        std::fs::canonicalize(root.path()).unwrap()
    };
    let (app, locks) = (base.join("app"), base.join("locks"));
    // Every spawn is timed: the three that register the catalog's profiles,
    // the binary's first, cold start among them, then the opens main makes
    // at each launch.
    let mut times: Vec<Duration> = ["work", "play", "news"]
        .iter()
        .map(|id| open(&app, &locks, &["--profile", id]))
        .collect();
    times.extend((0..RUNS).map(|_| open(&app, &locks, &[])));
    let cold = times[0];
    times.sort();
    let (p50, p95) = (percentile(&times, 50), percentile(&times, 95));
    let max = *times.last().unwrap();
    eprintln!(
        "profile open ({}, {} spawns): cold {cold:?}, p50 {p50:?}, p95 {p95:?}, max {max:?}",
        if OPTIMIZED { "optimized" } else { "debug" },
        times.len()
    );
    if OPTIMIZED {
        if p95 < GATE_P95 {
            return;
        }
        // A shared runner can stall a run of spawns together: on Windows a
        // tail of ten slow ones in 103; on Linux a first run with a 371 ms
        // cold start and a 254 ms p95 around a 4 ms median, then 14 ms at
        // p95 when measured again. A miss is measured once more and judged
        // on that run alone: a stall slows one run, a slow binary slows both.
        // Pooling the two let one badly stalled run fail the gate (198 ms
        // pooled). The first run's cold start is in its own figures above.
        let mut again: Vec<Duration> = (0..RUNS).map(|_| open(&app, &locks, &[])).collect();
        again.sort();
        let again_p95 = percentile(&again, 95);
        eprintln!(
            "profile open (re-measured, {} spawns): p50 {:?}, p95 {again_p95:?}",
            again.len(),
            percentile(&again, 50),
        );
        if cfg!(windows) && !WINDOWS_BLOCKS && again_p95 >= GATE_P95 {
            eprintln!(
                "p95 {again_p95:?} misses the gate on Windows, which reports only while \
                 profile open stays in JS there (0013)"
            );
            return;
        }
        assert!(
            again_p95 < GATE_P95,
            "p95 {again_p95:?} misses the gate again (first run p95 {p95:?}): {times:?} then {again:?}"
        );
    } else {
        assert!(p50 < DEBUG_P50, "p50 {p50:?} in a debug build: {times:?}");
    }
}
