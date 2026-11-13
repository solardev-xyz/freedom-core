//! The latency gate (design 0013, PRF-3): `profile open`'s wall time, timed
//! around the spawn as main times it around `spawnSync`, the binary's first
//! (cold) spawn included.
//!
//! The gate is the optimized binary's, the one main ships: under 100 ms at
//! the 95th percentile on each OS's CI runner. A run that misses is measured
//! once more and judged on both runs pooled, as the cost gates are, so a
//! runner's stall doesn't fail it alone. CI's `profile gate` job runs
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

#![allow(clippy::unwrap_used, clippy::print_stderr)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");

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
        // A shared runner can stall a run of spawns together (on Windows, a
        // tail of ten slow ones in 103). As the cost gates do, a miss is
        // measured once more, and judged on both runs' spawns pooled: a noisy
        // run doesn't fail the gate alone, and a slow binary, which slows
        // both, still does. The first run's cold start stays in the pool.
        let mut again: Vec<Duration> = (0..RUNS).map(|_| open(&app, &locks, &[])).collect();
        again.sort();
        let mut pooled = times.clone();
        pooled.extend(again.iter().copied());
        pooled.sort();
        let pooled_p95 = percentile(&pooled, 95);
        eprintln!(
            "profile open (re-measured, {} spawns): p50 {:?}, p95 {:?}; pooled {} spawns: p95 {pooled_p95:?}",
            again.len(),
            percentile(&again, 50),
            percentile(&again, 95),
            pooled.len()
        );
        assert!(
            pooled_p95 < GATE_P95,
            "pooled p95 {pooled_p95:?} misses the gate (first run p95 {p95:?}): {times:?} then {again:?}"
        );
    } else {
        assert!(p50 < DEBUG_P50, "p50 {p50:?} in a debug build: {times:?}");
    }
}
