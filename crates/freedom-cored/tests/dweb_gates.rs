//! Design 0009's gates through the binary (step 5d): the bounds of its
//! Bounds table, the vault under dweb load, the core's resident memory,
//! and a realistic page. The test plays main, as in `dweb`'s `verify`
//! module ([`dweb_world`]), and prints what it measures.
//!
//! - **Fast, always run** (CI runs them with `--all-features`; the ones
//!   marked `testhooks` need it): admission under the shipped grants, and
//!   at 64 running / 256 waiting; 128 streams; main's 256 outstanding
//!   pieces; the writer's windows, and its 8 MiB cap under 16 MiB of
//!   credit; `vault.lock` under 64 streaming bodies for 2 s; a realistic
//!   page with no round trip.
//! - **Heavy, `#[ignore]`d:** `vault.lock` for 10 s, the resident memory
//!   under the heaviest mixes, and the realistic page at 50 and 200 ms
//!   round trips:
//!
//!   ```sh
//!   cargo test -p freedom-cored --all-features --test dweb_gates -- --ignored --nocapture --test-threads 1
//!   # Release figures: the hooks are refused in optimized builds, so the
//!   # tests that need them drop out, and the vault test runs 64 requests
//!   # under the shipped grants (50 stream at once).
//!   cargo test --release -p freedom-cored --test dweb_gates -- --include-ignored --nocapture --test-threads 1
//!   ```
//!
//! **What the grants leave reachable.** The shipped 101 MiB of grants run
//! at most 50 Swarm or 12 IPFS requests. A Swarm request streams one
//! piece at a time beside one chunk, an IPFS request at most 8 blocks, so
//! under the shipped bounds at most 50 bodies stream at once, about 98
//! pieces stream, and the dweb thread's pieces never reach main's 256.
//! The tests that pin the 64 running, the 128 streams, the 256 pieces and
//! the 64 bodies' windows lift the bounds in front of them with
//! `FREEDOM_CORED_TEST_DWEB_GRANTS_BYTES` and `FREEDOM_CORED_TEST_DWEB_STREAMS`.
//! 0009's vault gate counts the 50 bodies the grants admit (the release
//! run); the 64-body runs are stress checks. 64 windows are exactly the
//! writer's 8 MiB, so the test that presses on that cap runs 128 bodies
//! (`FREEDOM_CORED_TEST_DWEB_RUNNING`) and reads the writer's high-water
//! mark from `FREEDOM_CORED_TEST_DWEB_WRITER_MARKER`'s file.
//!
//! **Resident memory** is read from `/proc` (`VmRSS`, `VmHWM`), as
//! `vault`'s tests read it: Linux only. Elsewhere it is not measured. The
//! peak is charged against an otherwise identical core after a protocol-1
//! hello, which starts no dweb thread, so the thread's start counts too.

// The gates print what they measure.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

mod common;
mod dweb_world;

use std::time::{Duration, Instant};

use dweb_world::*;
use serde_json::{Value, json};

const MIB: usize = 1 << 20;
/// Lifted grants: more than any test here runs.
#[cfg(feature = "testhooks")]
const LIFTED: (&str, &str) = ("FREEDOM_CORED_TEST_DWEB_GRANTS_BYTES", "4294967296");
/// The engine's bounds (`dweb::engine`), and what the shipped grants run.
const RUNNING: usize = 64;
const WAITING: usize = 256;
const SWARM_AT_ONCE: usize = 50;
const IPFS_AT_ONCE: usize = 12;
const GRANT_WAIT: Duration = Duration::from_secs(10);
/// The dweb writer's cap on queued body bytes (`dweb::thread`), and the
/// least a push takes when the cap would cut it (`fc_protocol::stream`).
const WRITER_DATA_CAP: usize = 8 * MIB;
#[cfg(feature = "testhooks")]
const SMALL_FRAME: usize = 4 << 10;
/// The file the dweb thread writes its writer's high-water mark to
/// (`testhooks`; without it, no file).
const WRITER_MARKER: &str = "FREEDOM_CORED_TEST_DWEB_WRITER_MARKER";

/// How far past its bound a timing may run in CI (a debug build on a
/// shared runner). The figures are printed either way.
const SLACK: Duration = Duration::from_secs(3);

fn swarm_64m() -> Value {
    params(
        plan(json!({ "swarm": FILE_64M }), "/file.bin", json!([])),
        "GET",
        None,
    )
}

fn ipfs_file(root: &str) -> Value {
    params(
        plan(json!({ "ipfs": root }), "", json!([])),
        "GET",
        Some(false),
    )
}

/// Percentiles of `samples`, in ms.
struct Spread {
    n: usize,
    p50: f64,
    p90: f64,
    p99: f64,
    max: f64,
}

fn spread(samples: &[Duration]) -> Spread {
    let mut v: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1e3).collect();
    v.sort_by(f64::total_cmp);
    let at = |p: f64| {
        if v.is_empty() {
            return f64::NAN;
        }
        let i = ((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1;
        v[i]
    };
    Spread {
        n: v.len(),
        p50: at(0.50),
        p90: at(0.90),
        p99: at(0.99),
        max: at(1.0),
    }
}

impl std::fmt::Display for Spread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "n {} p50 {:.1} ms p90 {:.1} ms p99 {:.1} ms max {:.1} ms",
            self.n, self.p50, self.p90, self.p99, self.max
        )
    }
}

/// The core's resident memory now and at its peak, in KiB (Linux only).
#[cfg(target_os = "linux")]
fn resident(m: &Main) -> Option<(u64, u64)> {
    Some(m.core.memory_kib())
}

#[cfg(not(target_os = "linux"))]
fn resident(_: &Main) -> Option<(u64, u64)> {
    None
}

/// What the gates charge the dweb thread against, in KiB.
#[derive(Debug, Clone, Copy)]
struct Base {
    /// An otherwise identical core's resident memory after a protocol-1
    /// hello: the event loop starts the dweb thread and its hashing pool
    /// only at protocol 2, so this is the core without them.
    no_dweb: u64,
    /// This core's after its protocol-2 hello, the dweb thread started.
    hello: u64,
}

/// The resident memory before the dweb thread: a second core, started
/// with `m`'s `env`, after a protocol-1 hello with fragments. Everything
/// `m` holds above it is the dweb thread's, its start included.
#[cfg(target_os = "linux")]
fn baseline(m: &Main, env: &[(&str, &str)]) -> Option<Base> {
    let hello = m.core.memory_kib().0;
    let (_dir, data, locks) = common::dirs();
    let mut v1 = common::spawn_env("serve", &data, &locks, &[], env);
    let reply = v1.hello_fragments();
    assert_eq!(reply["result"]["protocol"], 1, "{reply}");
    let (no_dweb, _) = v1.memory_kib();
    Some(Base { no_dweb, hello })
}

#[cfg(not(target_os = "linux"))]
fn baseline(_: &Main, _: &[(&str, &str)]) -> Option<Base> {
    None
}

/// Prints the core's peak resident memory against the core's without the
/// dweb thread, and checks the dweb thread, from its start through the
/// load, added at most its 128 MiB (0009, Bounds).
fn memory_within_bounds(m: &Main, base: Option<Base>, what: &str) {
    let (Some(Base { no_dweb, hello }), Some((now, peak))) = (base, resident(m)) else {
        eprintln!("[{what}] resident memory: not measured on this platform");
        return;
    };
    eprintln!(
        "[{what}] resident memory: {no_dweb} KiB without the dweb thread (protocol 1), \
         {hello} KiB after this core's hello, {now} KiB now, peak {peak} KiB (+{} KiB)",
        peak.saturating_sub(no_dweb)
    );
    assert!(
        peak <= no_dweb + 128 * 1024,
        "[{what}] peak {peak} KiB over {no_dweb} KiB without the dweb thread + 128 MiB"
    );
}

/// The dweb writer's high-water mark of queued body bytes, from its
/// marker file; `None` before it held any, or without `testhooks`.
fn writer_most(marker: &std::path::Path) -> Option<usize> {
    std::fs::read_to_string(marker).ok()?.trim().parse().ok()
}

/// Runs main for `d`.
fn run_for(m: &mut Main, d: Duration) {
    let until = Instant::now() + d;
    while Instant::now() < until {
        m.step(Duration::from_millis(5));
    }
}

/// Waits for `done`, failing after `within`.
fn wait_for(m: &mut Main, within: Duration, what: &str, done: impl Fn(&Main) -> bool) {
    let until = Instant::now() + within;
    while !done(m) {
        assert!(
            Instant::now() < until,
            "{what}: not within {within:?}; {} pieces asked, {} answers",
            m.asked.len(),
            m.got.values().filter(|g| g.result.is_some()).count()
        );
        m.step(Duration::from_millis(5));
    }
}

/// How many of `ids` ended `busy`, and how long each waited for it.
fn busy(m: &Main, ids: &[u64]) -> Vec<Duration> {
    ids.iter()
        .filter(|id| m.got[id].error_code() == Some("busy"))
        .map(|id| m.got[id].to_answer().unwrap())
        .collect()
}

/// Requests that wait 10 s for a grant end `busy`, and none sooner; past
/// 256 waiting, at once. `held` keeps every request at its first piece.
fn admission(m: &mut Main, running: usize, offer: impl Fn() -> Value, what: &str) {
    // Made first, then sent at once: none of them waits 10 s meanwhile.
    let offers: Vec<Value> = (0..running + WAITING + 2).map(|_| offer()).collect();
    let ids: Vec<u64> = offers.into_iter().map(|p| m.verify(p)).collect();
    let sent = Instant::now();
    let over = &ids[running + WAITING..];
    wait_for(m, Duration::from_secs(5), "busy at once", |m| {
        over.iter().all(|id| m.got[id].done())
    });
    let at_once = busy(m, over);
    assert_eq!(
        at_once.len(),
        over.len(),
        "{:?}",
        over.iter().map(|id| &m.got[id]).collect::<Vec<_>>()
    );
    // Each running request asked its first piece; nothing else did.
    wait_for(m, Duration::from_secs(10), "the running", |m| {
        m.asked.len() >= running
    });
    run_for(m, Duration::from_millis(500));
    assert_eq!(m.asked.len(), running, "[{what}] running");
    assert!(
        ids[..running + WAITING]
            .iter()
            .all(|id| m.got[id].result.is_none())
    );
    eprintln!(
        "[{what}] {running} running, {WAITING} waiting; past them busy at once: {}",
        spread(&at_once)
    );
    // The waiting end busy once they have waited 10 s for a grant.
    let waiting = &ids[running..running + WAITING];
    wait_for(
        m,
        GRANT_WAIT + SLACK + Duration::from_secs(2),
        "busy after the wait",
        |m| waiting.iter().all(|id| m.got[id].done()),
    );
    let waited = busy(m, waiting);
    assert_eq!(waited.len(), WAITING);
    let s = spread(&waited);
    eprintln!(
        "[{what}] the {WAITING} waiting ended busy after {s}; {:?} since the first was sent",
        sent.elapsed()
    );
    // The thread's clock counts whole milliseconds.
    assert!(
        waited
            .iter()
            .all(|w| *w + Duration::from_millis(2) >= GRANT_WAIT),
        "{s}"
    );
    assert!(waited.iter().all(|w| *w < GRANT_WAIT + SLACK), "{s}");
    // The running are still running.
    assert_eq!(m.asked.len(), running);
    assert!(ids[..running].iter().all(|id| m.got[id].result.is_none()));
    for &id in &ids[..running] {
        m.cancel(id);
    }
    wait_for(m, Duration::from_secs(10), "cancelled", |m| {
        ids[..running].iter().all(|id| m.got[id].done()) && m.held.is_empty()
    });
    for id in &ids[..running] {
        assert_eq!(m.got[id].error_code(), Some("cancelled"));
    }
}

#[test]
fn admission_under_the_shipped_grants() {
    // Swarm: 50 grants of 2 MiB; then IPFS, 12 of 8 MiB.
    let mut m = Main::new(World::new().change("/chunks/", Answer::Hold));
    let base = baseline(&m, &[]);
    admission(&mut m, SWARM_AT_ONCE, || swarm("/index.html"), "swarm");
    m.world = World::new().change("/ipfs/", Answer::Hold);
    m.asked.clear();
    admission(&mut m, IPFS_AT_ONCE, || ipfs("/index.html", false), "ipfs");
    // The core goes on.
    m.world = World::new();
    let id = m.verify(swarm("/index.html"));
    m.settle(&[id]);
    assert_eq!(m.got[&id].body, content("site-index", 300));
    memory_within_bounds(&m, base, "admission");
}

#[cfg(feature = "testhooks")]
#[test]
fn admission_at_64_running_and_256_waiting() {
    let mut m = Main::with_env(World::new().change("/chunks/", Answer::Hold), &[LIFTED]);
    let offers: Vec<Value> = (0..RUNNING + WAITING + 2)
        .map(|_| swarm("/index.html"))
        .collect();
    let ids: Vec<u64> = offers.into_iter().map(|p| m.verify(p)).collect();
    let over = &ids[RUNNING + WAITING..];
    wait_for(&mut m, Duration::from_secs(5), "busy at once", |m| {
        over.iter().all(|id| m.got[id].done())
    });
    assert_eq!(busy(&m, over).len(), 2);
    wait_for(&mut m, Duration::from_secs(10), "the running", |m| {
        m.asked.len() >= RUNNING
    });
    run_for(&mut m, Duration::from_millis(500));
    assert_eq!(m.asked.len(), RUNNING);
    eprintln!("[64/256] busy at once: {}", spread(&busy(&m, over)));
    // As the running end, the waiting run in their place.
    for &id in &ids[..RUNNING] {
        m.cancel(id);
    }
    wait_for(&mut m, Duration::from_secs(10), "the next 64", |m| {
        m.asked.len() == 2 * RUNNING
    });
    run_for(&mut m, Duration::from_millis(500));
    assert_eq!(m.asked.len(), 2 * RUNNING);
    for id in &ids[..RUNNING] {
        assert_eq!(m.got[id].error_code(), Some("cancelled"));
    }
    assert!(
        ids[RUNNING..RUNNING + WAITING]
            .iter()
            .all(|id| m.got[id].result.is_none())
    );
}

/// 64 IPFS reads of the 10 MiB file whose leaves main holds: they would
/// ask 512 blocks at once, 8 each.
#[cfg(feature = "testhooks")]
fn held_leaves(env: &[(&str, &str)], bound: usize) -> (Main, Vec<u64>) {
    let mut m = Main::with_env(World::new().change("/ipfs/bafkrei", Answer::Hold), env);
    let ids: Vec<u64> = (0..RUNNING)
        .map(|_| m.verify(ipfs_file(IPFS_10M)))
        .collect();
    // Each read's root block, then its leaves until the bound stops them.
    wait_for(&mut m, Duration::from_secs(30), "the leaves", |m| {
        m.held.len() >= bound
    });
    run_for(&mut m, Duration::from_millis(500));
    (m, ids)
}

/// Cancels one read: its held blocks go, and others' waiting blocks take
/// their place, up to the same bound.
#[cfg(feature = "testhooks")]
fn one_ends(m: &mut Main, id: u64) -> usize {
    let asked = m.asked.len();
    m.cancel(id);
    wait_for(m, Duration::from_secs(10), "cancelled", |m| {
        m.got[&id].done()
    });
    run_for(m, Duration::from_millis(500));
    m.asked.len() - asked
}

#[cfg(feature = "testhooks")]
#[test]
fn streams_stay_within_128() {
    let (mut m, ids) = held_leaves(&[LIFTED], 128);
    assert_eq!(m.streams, 128, "{}", m.asked.len());
    assert_eq!(m.most_streams, 128);
    assert_eq!(m.held.len(), 128);
    let more = one_ends(&mut m, ids[0]);
    assert!(more > 0, "nothing took the freed streams");
    assert_eq!((m.streams, m.most_streams), (128, 128));
    eprintln!("[streams] 64 reads, 128 streams held; one cancelled, {more} more asked");
    // The vault isn't behind them.
    let lock = m.lock();
    m.settle(&[lock]);
    for &id in &ids[1..] {
        m.cancel(id);
    }
    m.settle(&ids);
    run_for(&mut m, Duration::from_millis(200));
    assert_eq!((m.streams, m.held.len()), (0, 0));
}

#[cfg(feature = "testhooks")]
#[test]
fn outstanding_pieces_stay_within_256() {
    let (mut m, ids) = held_leaves(&[LIFTED, ("FREEDOM_CORED_TEST_DWEB_STREAMS", "4096")], 256);
    assert_eq!(m.unanswered, 256, "{}", m.asked.len());
    assert_eq!(m.most_unanswered, 256);
    let more = one_ends(&mut m, ids[0]);
    assert!(more > 0, "nothing took the freed pieces");
    assert_eq!((m.unanswered, m.most_unanswered), (256, 256));
    eprintln!("[pieces] 64 reads, 256 pieces held at main; one cancelled, {more} more asked");
    let lock = m.lock();
    let forget = m.call("dweb.forget", json!({ "partition": null }));
    m.settle(&[lock, forget]);
    // Main answers them all: every read completes, verified.
    m.keep_bodies = false;
    m.release_held();
    let rest = &ids[1..];
    let start = Instant::now();
    wait_for(&mut m, Duration::from_secs(300), "the reads", |m| {
        rest.iter().all(|id| m.got[id].done())
    });
    for id in rest {
        assert_eq!(
            (m.got[id].len, m.got[id].ended),
            (10 * MIB, true),
            "{:?}",
            m.got[id]
        );
    }
    assert_eq!(m.most_unanswered, 256);
    eprintln!(
        "[pieces] then 63 × 10 MiB verified in {:?}",
        start.elapsed()
    );
}

/// The core with `env` and the dweb writer's marker file, in a directory
/// of its own (kept as long as the core runs; written with `testhooks`).
fn with_writer_marker(
    env: &[(&str, &str)],
) -> (Main, Option<Base>, tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("writer-most");
    let env: Vec<(&str, &str)> = env
        .iter()
        .copied()
        .chain([(WRITER_MARKER, marker.to_str().unwrap())])
        .collect();
    let m = Main::with_env(World::new(), &env);
    let base = baseline(&m, &env);
    (m, base, dir, marker)
}

/// The verified bodies main doesn't read: each gets its window and no
/// more, the writer holds them while main's reads pause, and all of them
/// come once it reads again. The writer's queue never holds more than
/// those windows, nor its cap.
fn windows(env: &[(&str, &str)], bodies: usize, what: &str) {
    let (mut m, base, _dir, marker) = with_writer_marker(env);
    m.credits_bodies = false;
    m.keep_bodies = false;
    let ids: Vec<u64> = (0..RUNNING).map(|_| m.verify(swarm_64m())).collect();
    let headed = |g: &Got| g.result.as_ref().is_some_and(|r| r.get("result").is_some());
    let open = |m: &Main| ids.iter().filter(|id| headed(&m.got[id])).count();
    wait_for(&mut m, Duration::from_secs(60), "the heads", |m| {
        open(m) == bodies
    });
    // Main stops reading for a second: the core's writer holds what it
    // made of the windows.
    m.core.pause_reading();
    std::thread::sleep(Duration::from_secs(1));
    let paused = resident(&m);
    m.core.resume_reading();
    wait_for(&mut m, Duration::from_secs(60), "the windows", |m| {
        ids.iter().map(|id| m.got[id].len).sum::<usize>() == bodies * WINDOW
    });
    run_for(&mut m, Duration::from_secs(1));
    let total: usize = ids.iter().map(|id| m.got[id].len).sum();
    assert_eq!(total, bodies * WINDOW);
    assert_eq!(open(&m), bodies);
    for id in &ids {
        let want = if headed(&m.got[id]) { WINDOW } else { 0 };
        assert_eq!(m.got[id].len, want);
    }
    let most = writer_most(&marker);
    eprintln!(
        "[{what}] {bodies} bodies, uncredited: {total} bytes, {} KiB each; paused reader at {paused:?} KiB; \
         the writer's queue held at most {most:?} bytes",
        WINDOW >> 10
    );
    if cfg!(feature = "testhooks") {
        let most = most.expect("the writer's high-water mark");
        assert!(
            most > 0 && most <= WRITER_DATA_CAP.min(bodies * WINDOW),
            "{most}"
        );
    }
    memory_within_bounds(&m, base, what);
}

#[test]
fn the_writer_holds_the_windows_under_the_shipped_grants() {
    windows(&[], SWARM_AT_ONCE, "windows, shipped grants");
}

#[cfg(feature = "testhooks")]
#[test]
fn the_writer_holds_64_windows() {
    // 64 × 128 KiB: 0009's 8 MiB of the dweb writer.
    windows(&[LIFTED], RUNNING, "windows, 64 bodies");
}

/// The writer's cap under pressure: 128 bodies (grants and running
/// lifted), each read to its window uncredited, so every one waits on
/// main with its next piece's bytes in hand. Main stops reading and
/// credits each body another window: 16 MiB press on the writer's 8 MiB.
/// Its queue fills to the cap, short of it by less than the 4 KiB a push
/// waits for, and never past it; the rest waits in the bodies' own queues
/// and comes once main reads again.
#[cfg(feature = "testhooks")]
#[test]
fn the_writer_holds_at_most_8_mib() {
    use common::{KIND_STREAM_CREDIT, stream_frame};
    let bodies = 2 * RUNNING;
    let (mut m, base, _dir, marker) =
        with_writer_marker(&[LIFTED, ("FREEDOM_CORED_TEST_DWEB_RUNNING", "128")]);
    m.credits_bodies = false;
    m.keep_bodies = false;
    let ids: Vec<u64> = (0..bodies).map(|_| m.verify(swarm_64m())).collect();
    let got = |m: &Main| ids.iter().map(|id| m.got[id].len).sum::<usize>();
    wait_for(&mut m, Duration::from_secs(60), "the windows", |m| {
        got(m) == bodies * WINDOW
    });
    // Main sends what the core's credit allows of their pieces meanwhile.
    run_for(&mut m, Duration::from_millis(500));
    let windows = writer_most(&marker).unwrap_or(0);
    m.core.pause_reading();
    let credit = u32::try_from(WINDOW).unwrap().to_be_bytes();
    for &id in &ids {
        m.core
            .send_raw(&stream_frame(KIND_STREAM_CREDIT, id, &credit));
    }
    // Until the writer's queue stops growing.
    let (mut most, mut since) = (writer_most(&marker).unwrap_or(0), Instant::now());
    let until = Instant::now() + Duration::from_secs(30);
    while since.elapsed() < Duration::from_secs(1) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
        let now = writer_most(&marker).unwrap_or(0);
        if now != most {
            (most, since) = (now, Instant::now());
        }
    }
    let paused = resident(&m);
    m.core.resume_reading();
    wait_for(&mut m, Duration::from_secs(60), "the second windows", |m| {
        got(m) == bodies * 2 * WINDOW
    });
    run_for(&mut m, Duration::from_millis(500));
    eprintln!(
        "[writer cap] {bodies} bodies; the writer's queue held at most {windows} bytes for their \
         windows, then {most} bytes (cap {WRITER_DATA_CAP}) for 16 MiB of credit with main's \
         reads paused, at {paused:?} KiB"
    );
    assert!(
        most > WRITER_DATA_CAP - SMALL_FRAME && most <= WRITER_DATA_CAP,
        "the writer's queue held at most {most} bytes, not the cap {WRITER_DATA_CAP}"
    );
    assert_eq!(got(&m), bodies * 2 * WINDOW, "nothing past the credit");
    for &id in &ids {
        m.cancel(id);
    }
    m.settle(&ids);
    memory_within_bounds(&m, base, "writer cap");
}

/// `vault.lock` every 20 ms for `d`, while 64 Swarm reads of 64 MiB
/// stream at full speed: main reads and credits each body at once.
fn vault_under_load(env: &[(&str, &str)], d: Duration) -> (Spread, usize) {
    let mut m = Main::with_env(World::new(), env);
    let base = baseline(&m, env);
    m.keep_bodies = false;
    let ids: Vec<u64> = (0..RUNNING).map(|_| m.verify(swarm_64m())).collect();
    let streaming = |m: &Main| ids.iter().filter(|id| m.got[id].len > 0).count();
    let bodies = if env.is_empty() {
        SWARM_AT_ONCE
    } else {
        RUNNING
    };
    wait_for(&mut m, Duration::from_secs(60), "the bodies", |m| {
        streaming(m) >= bodies
    });
    let before: usize = ids.iter().map(|id| m.got[id].len).sum();
    let start = Instant::now();
    let mut next = start;
    let mut locks = Vec::new();
    while start.elapsed() < d {
        if Instant::now() >= next {
            locks.push(m.lock());
            next += Duration::from_millis(20);
        }
        m.step(Duration::from_millis(1));
    }
    let moved: usize = ids.iter().map(|id| m.got[id].len).sum::<usize>() - before;
    let elapsed = start.elapsed();
    let live = ids
        .iter()
        .filter(|id| m.got[id].len > 0 && !m.got[id].done())
        .count();
    wait_for(&mut m, Duration::from_secs(10), "the last locks", |m| {
        locks.iter().all(|id| m.got[id].done())
    });
    for id in &locks {
        assert_eq!(m.result(*id), &json!({}));
    }
    let samples: Vec<Duration> = locks
        .iter()
        .map(|id| m.got[id].to_answer().unwrap())
        .collect();
    let s = spread(&samples);
    eprintln!(
        "[vault] {bodies} bodies streaming ({live} still at the end), {:.1} MiB/s verified to main over {elapsed:?}; vault.lock: {s}",
        moved as f64 / MIB as f64 / elapsed.as_secs_f64()
    );
    assert!(moved > 0);
    for &id in &ids {
        m.cancel(id);
    }
    m.settle(&ids);
    memory_within_bounds(&m, base, "vault");
    (s, bodies)
}

#[cfg(feature = "testhooks")]
#[test]
fn vault_lock_is_answered_under_64_streaming_bodies() {
    let (s, _) = vault_under_load(&[LIFTED], Duration::from_secs(2));
    // A debug build on a shared runner: a loose bound. The heavy run
    // prints the release figure.
    assert!(s.p99 < 1_000.0, "{s}");
}

#[test]
#[ignore]
fn vault_lock_under_load_heavy() {
    #[cfg(feature = "testhooks")]
    let env: &[(&str, &str)] = &[LIFTED];
    #[cfg(not(feature = "testhooks"))]
    let env: &[(&str, &str)] = &[];
    let (s, bodies) = vault_under_load(env, Duration::from_secs(10));
    let bound = if cfg!(debug_assertions) {
        1_000.0
    } else {
        50.0
    };
    eprintln!(
        "[vault, heavy] {bodies} bodies; p99 {:.1} ms against {bound} ms",
        s.p99
    );
    assert!(s.p99 <= bound, "{s}");
}

/// What a realistic page asks at once: about 100 small IPFS objects, 3
/// long IPFS reads, and some Swarm (one long read among them), each piece
/// answered after `rtt`. Busy anywhere fails it: that is the design's
/// question, not the test's.
fn page(rtt: Duration) {
    page_of(rtt, 100, true);
}

/// The page with `small` small IPFS objects (the long reads and the Swarm
/// scale with them); how many ended `busy`. Unless `strict`, those are
/// reported, not failed.
fn page_of(rtt: Duration, small: usize, strict: bool) -> usize {
    let d = vectors("dweb-verify.json");
    let site: Vec<(String, Vec<u8>)> = d["ipfs"]["directories"]
        .as_array()
        .unwrap()
        .iter()
        .find(|dir| dir["id"] == "site-v1")
        .unwrap()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            [
                "index.html",
                "style.css",
                "docs/page.html",
                "docs/sub/x.txt",
                "img/photo.jpg",
                "page",
                "data",
            ]
            .contains(&e["path"].as_str().unwrap())
        })
        .map(|e| {
            let size = e["size"].as_u64().unwrap() as usize;
            let bytes = match (e["text"].as_str(), e["seed"].as_str()) {
                (Some(t), _) => t.as_bytes().to_vec(),
                (_, Some(seed)) => content(seed, size),
                _ => unreachable!(),
            };
            (format!("/{}", e["path"].as_str().unwrap()), bytes)
        })
        .collect();
    assert_eq!(site.len(), 7);
    let ant = [
        ("/index.html", content("site-index", 300)),
        ("/style.css", content("site-style", 5000)),
    ];
    let mut m = Main::new(World::new());
    let base = baseline(&m, &[]);
    m.delay = rtt;
    // id → (class, the body it must get, or its length)
    let mut want: Vec<(u64, &str, Option<Vec<u8>>, usize)> = Vec::new();
    let mut ask = |m: &mut Main, class, p: Value, body: Option<Vec<u8>>, len: usize| {
        let id = m.verify(p);
        want.push((id, class, body, len));
    };
    // The page's video first, then its long reads among the small ones.
    let start = Instant::now();
    ask(&mut m, "swarm long", swarm_64m(), None, (64 << 20) + 1);
    for i in 0..small {
        if i % 34 == 0 {
            ask(&mut m, "ipfs long", ipfs_file(IPFS_10M), None, 10 * MIB);
        }
        if i % 5 == 0 {
            let (path, body) = &ant[(i / 5) % 2];
            ask(
                &mut m,
                "swarm small",
                swarm(path),
                Some(body.clone()),
                body.len(),
            );
        }
        let (path, body) = &site[i % site.len()];
        ask(
            &mut m,
            "ipfs small",
            ipfs(path, false),
            Some(body.clone()),
            body.len(),
        );
    }
    let ids: Vec<u64> = want.iter().map(|w| w.0).collect();
    wait_for(&mut m, Duration::from_secs(600), "the page", |m| {
        ids.iter().all(|id| m.got[id].done())
    });
    let total = start.elapsed();
    let mut report = String::new();
    let mut busy = 0;
    for class in ["ipfs small", "ipfs long", "swarm small", "swarm long"] {
        let of: Vec<_> = want.iter().filter(|w| w.1 == class).collect();
        let heads: Vec<Duration> = of
            .iter()
            .map(|w| m.got[&w.0].to_answer().unwrap())
            .collect();
        let ends: Vec<Duration> = of
            .iter()
            .filter_map(|w| Some(m.got[&w.0].finished? - m.got[&w.0].sent))
            .collect();
        busy += of
            .iter()
            .filter(|w| m.got[&w.0].error_code() == Some("busy"))
            .count();
        report += &format!(
            "\n  {class} ×{}: head {}; body end {}",
            of.len(),
            spread(&heads),
            spread(&ends),
        );
    }
    eprintln!(
        "[page, {} ms round trip] {} requests ({small} small IPFS) in {total:?}, {} pieces, {busy} busy:{report}",
        rtt.as_millis(),
        want.len(),
        m.asked.len()
    );
    for (id, class, body, len) in &want {
        let got = &m.got[id];
        if !strict && got.error_code() == Some("busy") {
            continue;
        }
        assert_eq!(got.error_code(), None, "{class}: {got:?}");
        assert_eq!(m.result(*id)["trust"]["content"], "verified", "{class}");
        assert!(got.ended, "{class}: {got:?}");
        assert_eq!(got.len, *len, "{class}");
        if let Some(body) = body {
            assert_eq!(&got.body, body, "{class}");
        }
    }
    memory_within_bounds(&m, base, "page");
    busy
}

#[test]
fn a_realistic_page_loads_without_busy() {
    page(Duration::ZERO);
}

#[test]
#[ignore]
fn a_realistic_page_at_50_ms() {
    page(Duration::from_millis(50));
}

#[test]
#[ignore]
fn a_realistic_page_at_200_ms() {
    page(Duration::from_millis(200));
}

/// The margin, measured, not gated: twice the page at 200 ms, and how
/// many of its requests end `busy`.
#[test]
#[ignore]
fn a_page_twice_as_big_at_200_ms() {
    let busy = page_of(Duration::from_millis(200), 200, false);
    eprintln!("[page ×2, 200 ms round trip] {busy} busy");
}

/// The heaviest mixes under the shipped bounds, one after another on one
/// core: 50 Swarm bodies streaming, 12 IPFS reads whose bodies main
/// doesn't read while its reads pause, and a page.
#[test]
#[ignore]
fn resident_memory_stays_within_128_mib() {
    let mut m = Main::new(World::new());
    let base = baseline(&m, &[]);
    m.keep_bodies = false;
    let swarm: Vec<u64> = (0..SWARM_AT_ONCE).map(|_| m.verify(swarm_64m())).collect();
    run_for(&mut m, Duration::from_secs(5));
    eprintln!("[memory] 50 Swarm bodies streaming: {:?}", resident(&m));
    for &id in &swarm {
        m.cancel(id);
    }
    m.settle(&swarm);
    m.credits_bodies = false;
    let ipfs: Vec<u64> = (0..IPFS_AT_ONCE + 4)
        .map(|_| m.verify(ipfs_file(IPFS_10M)))
        .collect();
    run_for(&mut m, Duration::from_secs(3));
    m.core.pause_reading();
    std::thread::sleep(Duration::from_secs(2));
    eprintln!(
        "[memory] 12 IPFS bodies unread, main's reads paused: {:?}",
        resident(&m)
    );
    m.core.resume_reading();
    for &id in &ipfs {
        m.cancel(id);
    }
    m.settle(&ipfs);
    m.credits_bodies = true;
    memory_within_bounds(&m, base, "memory");
    drop(m);
    page(Duration::from_millis(20));
}
