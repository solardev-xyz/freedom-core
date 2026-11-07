//! The unit watchdog through the real binary (design 0008, "The unit
//! watchdog", "The escape", and "Tests first": "Units and the watchdog"): a
//! unit that hangs ends the process with 70, its record and the marker
//! kept; the next start reruns it; a unit in progress when two processes
//! ended quarantines its repository; every kind of unit leaves its record.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::fixture;
use common::*;
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::state::State;
use serde_json::{Value, json};

/// The hung unit's limit in these tests (`FREEDOM_RADICLED_TEST_HANG_LIMIT_MS`),
/// short, so that it ends its process quickly. Only the hung unit's kind
/// gets it: every unit before it keeps its 30 s, so one that a slow
/// runner's disk holds up never fires in its place (on Windows CI, with
/// four processes' fsyncs at once, `ref-locks` has taken 2.6 s and `begin`
/// 3.3 s).
const LIMIT_MS: u64 = 3000;

/// Every kind of unit heartwood's driver runs, as its records name them.
const KINDS: [&str; 11] = [
    "clone",
    "begin",
    "ref-locks",
    "namespace-begin",
    "namespace",
    "resign",
    "cache-scan",
    "cache-list",
    "cache",
    "cache-commit",
    "publish",
];

/// A home where every kind of unit runs: a repository of the running
/// identity's with a ref its signed refs don't sign, a temporary clone, and
/// the marker naming the identity.
fn dirty_home(dirs: &Dirs, name: &str) -> RepoId {
    let rid = fixture::repository(&dirs.home, &SEED, name);
    fixture::unsigned_ref(&dirs.home, rid, NID);
    let clone = dirs
        .home
        .join("storage")
        .join(format!("{}.tmp", rid.canonical()));
    std::fs::create_dir_all(clone.join("objects")).unwrap();
    fixture::mark(&dirs.home, &[NID]);
    rid
}

/// A process through `rad.identity` with the fixture's key, and `extra`.
fn identified(dirs: &Dirs, extra: &[(&str, &str)]) -> Radicled {
    let mut radicled = Radicled::serve(dirs, extra);
    let hello = radicled.hello();
    let identity = radicled.call("rad.identity", sealed_to(&hello, &SEED));
    assert!(identity["result"].is_object(), "{identity}");
    radicled
}

/// A start whose first unit of `kind` hangs: the process ends with 70 and
/// logs `unit_overrun`, without answering `rad.reconcile`, and the bound
/// that ran out is the hung unit's own limit. However long the units before
/// it took, theirs are 30 s: only the hung kind's is [`LIMIT_MS`]. With the
/// unit the record shows in progress (the callers' checks), that is the
/// hung unit ended by its limit, and by nothing later, without timing the
/// run on the test's clock.
fn hang(dirs: &Dirs, kind: &str) {
    let limit = LIMIT_MS.to_string();
    let mut radicled = identified(
        dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HANG_UNIT", kind),
            ("FREEDOM_RADICLED_TEST_HANG_LIMIT_MS", &limit),
        ],
    );
    radicled.request("rad.reconcile", json!({}));
    assert_eq!(
        radicled.exit_code(OVERRUN_EXIT_TIMEOUT),
        Some(70),
        "a {kind} unit that hangs ends the process"
    );
    let log = radicled.stderr();
    assert_eq!(overrun(&log)["bound_ms"], LIMIT_MS, "{kind}: {log}");
}

fn reconcile(dirs: &Dirs) -> Value {
    let mut radicled = identified(dirs, &[]);
    radicled.call("rad.reconcile", json!({}))
}

/// The units in progress the home's state records, by kind, and how many
/// processes started each.
fn in_progress(home: &Path) -> Vec<(String, u32)> {
    State::open(home.join("cobs").join("cache.db"))
        .unwrap()
        .histories()
        .unwrap()
        .into_iter()
        .map(|unit| (unit.unit.kind, unit.attempts))
        .collect()
}

#[test]
fn a_hung_unit_ends_the_process_and_the_next_start_finishes_it() {
    let dirs = Dirs::new();
    dirty_home(&dirs, "hung");
    hang(&dirs, "cache");
    // The record and the marker survive the process.
    assert_eq!(in_progress(&dirs.home), [("cache".to_owned(), 1)]);
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    // The next start reruns it, and finishes.
    let reply = reconcile(&dirs);
    assert_eq!(reply["result"]["was_dirty"], true, "{reply}");
    assert_eq!(reply["result"]["repaired"]["caches"], 1, "{reply}");
    assert_eq!(reply["result"]["quarantined"]["count"], 0, "{reply}");
    assert!(in_progress(&dirs.home).is_empty());
}

#[test]
fn a_unit_in_progress_when_two_processes_ended_quarantines_its_repository() {
    let dirs = Dirs::new();
    let rid = dirty_home(&dirs, "poison");
    hang(&dirs, "cache");
    hang(&dirs, "cache");
    assert_eq!(in_progress(&dirs.home), [("cache".to_owned(), 2)]);

    let reply = reconcile(&dirs);
    let quarantined = &reply["result"]["quarantined"];
    assert_eq!(quarantined["count"], 1, "{reply}");
    assert_eq!(quarantined["first"][0]["rid"], rid.to_string(), "{reply}");
    assert_eq!(quarantined["first"][0]["kind"], "cache", "{reply}");
    // Its git data stays.
    assert!(fixture::storage_of(&dirs.home, rid).is_dir());
}

#[test]
fn every_kind_of_unit_leaves_a_record_the_next_start_finds() {
    for kind in KINDS {
        let dirs = Dirs::new();
        dirty_home(&dirs, kind);
        hang(&dirs, kind);
        let found = in_progress(&dirs.home);
        assert!(
            found
                .iter()
                .any(|(k, attempts)| k == kind && *attempts == 1),
            "{kind}: {found:?}"
        );
    }
}

/// A unit that returns within its limit, as every unit of a healthy run
/// does, never fires the watchdog: a run with a short limit completes.
#[test]
fn units_that_return_in_time_never_fire() {
    let dirs = Dirs::new();
    dirty_home(&dirs, "healthy");
    let mut radicled = identified(&dirs, &[("FREEDOM_RADICLED_TEST_UNIT_LIMIT_MS", "5000")]);
    let reply = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reply["result"]["repaired"]["resigned"], 1, "{reply}");
    // Past the limit, the process is still here, and starts its node.
    std::thread::sleep(Duration::from_millis(5_500));
    let reply = radicled.call("rad.start", json!({ "alias": "x" }));
    assert!(reply["result"].is_object(), "{reply}");
}
