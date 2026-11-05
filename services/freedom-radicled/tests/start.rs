//! `rad.start` and the node's life through the real binary (design 0008,
//! "Start, stop and reconciliation", "Crashes and restarts", "Seeding and
//! serving" and "Tests first": "a failed start that exits", "a killed node
//! thread (exit 70)", "the 5 s shutdown", "a key file present").
//!
//! Every node here reaches no one: its home's `config.json` is the test
//! network's, with no seeds and a static peer set ([`configure`]), and a
//! build with the test hooks holds its dial gate to loopback.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::fixture::{self, OTHER_SEED};
use common::*;
use radicle::node::routing::Store as _;
use radicle::prelude::{NodeId, RepoId};
use serde_json::json;

/// Whether `nid` seeds `rid`, as `home`'s routing table says: a node's start
/// puts there every repository in storage that it seeds, and no other.
fn inventoried(home: &Path, rid: RepoId, nid: &str) -> bool {
    let nid: NodeId = nid.parse().unwrap();
    radicle::profile::Home::new(home.to_path_buf())
        .unwrap()
        .routing(Default::default())
        .unwrap()
        .get(&rid)
        .unwrap()
        .contains(&nid)
}

/// What `home`'s `keys/` holds: libradicle makes the directory, and the
/// service writes nothing in it.
fn keys(home: &Path) -> Vec<String> {
    std::fs::read_dir(home.join("keys"))
        .map(|dir| {
            dir.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Waits up to `within` for `done`.
fn eventually(within: Duration, done: impl Fn() -> bool) -> bool {
    let until = Instant::now() + within;
    while !done() {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

#[test]
fn the_node_runs_as_the_sealed_key_and_a_clean_stop_clears_the_marker() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[]);
    let started = radicled.start();
    // The profile's alias: `alias` names a home that has none yet.
    assert_eq!(
        started["result"],
        json!({ "did": format!("did:key:{NID}"), "nid": NID, "alias": "quiet" }),
        "{started}"
    );
    // Present while the node runs.
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
    // Still starting nothing else: the reads come with later steps.
    let reply = radicled.call("rad.stats", json!({}));
    assert_eq!(reply["error"]["code"], "stopped", "{reply}");

    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);
    // No key was written, and no log line carries it.
    assert_eq!(keys(&dirs.home), Vec::<String>::new());
    let seed_hex: String = SEED.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!log.contains(&seed_hex));
}

/// A home with no profile yet: the start makes it, with the alias asked
/// for. Its defaults are the main network's, whose seeds the start's node
/// tries, and which the test hooks refuse before any lookup.
#[test]
fn a_fresh_home_gets_the_alias_asked_for() {
    let dirs = Dirs::new();
    let mut radicled = Radicled::serve(&dirs, &[]);
    let started = radicled.start();
    assert_eq!(started["result"]["alias"], "started", "{started}");
    assert_eq!(started["result"]["nid"], NID, "{started}");
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert!(dirs.home.join("config.json").is_file());
    assert_eq!(keys(&dirs.home), Vec::<String>::new());
}

/// `rad.start` is admitted once, after `rad.reconcile`, with an alias
/// heartwood takes; anything else answers, then ends the process.
#[test]
fn rad_start_is_admitted_once_after_reconciliation() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));

    // Before rad.reconcile.
    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    radicled.call("rad.identity", sealed_to(&hello, &SEED));
    let reply = radicled.call("rad.start", json!({ "alias": "x" }));
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));

    // Params it doesn't take.
    for params in [
        json!({}),
        json!({ "alias": "two words" }),
        json!({ "alias": "x", "listen": [] }),
    ] {
        let mut radicled = Radicled::serve(&dirs, &[]);
        let hello = radicled.hello();
        radicled.call("rad.identity", sealed_to(&hello, &SEED));
        radicled.call("rad.reconcile", json!({}));
        let reply = radicled.call("rad.start", params.clone());
        assert_eq!(
            reply["error"]["code"], "invalid_argument",
            "{params}: {reply}"
        );
        assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    }

    // A second start. The process ends without `rad.shutdown`, so the
    // marker stays: only a proven clean stop clears it.
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    let reply = radicled.call("rad.start", json!({ "alias": "x" }));
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// A key file placed between `rad.identity` and `rad.start`: `rad.start`
/// checks again, and refuses (0008, "The switch").
#[test]
fn a_key_file_placed_before_rad_start_refuses_it() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    radicled.call("rad.identity", sealed_to(&hello, &SEED));
    radicled.call("rad.reconcile", json!({}));
    std::fs::create_dir_all(dirs.home.join("keys")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("nowhere", dirs.home.join("keys").join("radicle")).unwrap();
    #[cfg(not(unix))]
    std::fs::write(dirs.home.join("keys").join("radicle"), b"a key file").unwrap();
    let reply = radicled.call("rad.start", json!({ "alias": "x" }));
    assert_eq!(reply["error"]["code"], "key_file_present", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// libradicle's start fails (the node's database can't open): `start_failed`
/// with its message, then the process ends, and main doesn't restart it.
#[test]
fn a_failed_start_answers_start_failed_then_exits() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    radicled.call("rad.identity", sealed_to(&hello, &SEED));
    radicled.call("rad.reconcile", json!({}));
    std::fs::create_dir_all(dirs.home.join("node").join("node.db")).unwrap();
    let reply = radicled.call("rad.start", json!({ "alias": "x" }));
    assert_eq!(reply["error"]["code"], "start_failed", "{reply}");
    assert!(
        !reply["error"]["message"].as_str().unwrap().is_empty(),
        "{reply}"
    );
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

#[test]
fn rad_start_has_a_deadline() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_START_DEADLINE_MS", "0")]);
    let reply = radicled.start();
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// The node thread ends while the node should run: `node_down`, exit 70, a
/// crash main restarts. The marker stays.
#[test]
fn a_node_thread_that_ends_is_node_down() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_STOP_NODE", "1")]);
    assert!(radicled.start()["result"].is_object());
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(70));
    let log = radicled.stderr();
    assert!(log.contains(r#""reason":"node_down""#), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// The node is asked to stop behind the service's back as `rad.start`
/// answers, and `rad.shutdown` follows at once: whichever of the node's
/// watch and the stop takes the node first, it is `node_down`, exit 70, and
/// the marker stays. The stop doesn't take a node already stopping for one
/// it stopped itself.
#[test]
fn a_shutdown_right_after_the_node_ended_behind_it_is_node_down() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_STOP_NODE", "1")]);
    assert!(radicled.start()["result"].is_object());
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(70));
    let log = radicled.stderr();
    assert!(log.contains(r#""reason":"node_down""#), "{log}");
    assert!(!log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// The watch has published `Down`, and the test hook holds it there for
/// good, before it claims the exit; then `end` ends the connection. The stop
/// that takes the `Down` node claims exit 70 itself, and the marker stays.
fn ended_while_the_watch_holds_the_node_down(end: impl FnOnce(&mut Radicled)) {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_STOP_NODE", "1"),
            ("FREEDOM_RADICLED_TEST_HOLD_DOWN", "1"),
        ],
    );
    assert!(radicled.start()["result"].is_object());
    assert!(
        radicled.logs("test hook: the watch holds the node down", EXIT_TIMEOUT),
        "the watch didn't publish Down"
    );
    end(&mut radicled);
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(70));
    let log = radicled.stderr();
    assert!(
        log.contains("the node was down; the dirty marker stays"),
        "{log}"
    );
    assert!(!log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// `rad.shutdown` between the watch's `Down` and its claim of the exit.
#[test]
fn a_shutdown_while_the_watch_holds_the_node_down_is_node_down() {
    ended_while_the_watch_holds_the_node_down(Radicled::shutdown);
}

/// EOF between the watch's `Down` and its claim of the exit.
#[test]
fn an_eof_while_the_watch_holds_the_node_down_is_node_down() {
    ended_while_the_watch_holds_the_node_down(Radicled::close_stdin);
}

/// A node that doesn't stop within the shutdown's bound: the process still
/// exits, and the marker stays, since the stop isn't proven clean.
#[test]
fn a_stop_that_isnt_proven_clean_keeps_the_marker() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS", "0")]);
    assert!(radicled.start()["result"].is_object());
    let asked = Instant::now();
    radicled.shutdown();
    // Within the connection's 5 s exit.
    assert_eq!(radicled.exit_code(Duration::from_secs(8)), Some(0));
    assert!(asked.elapsed() < Duration::from_secs(8));
    let log = radicled.stderr();
    assert!(log.contains("the node didn't stop cleanly"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// `config.json`'s `allow` default is overridden: the node seeds a
/// repository with no policy of its own not (0008, "Seeding and serving";
/// libradicle's `Options::seeding_policy`), and `config.json` is as written.
#[test]
fn a_config_json_allow_default_is_overridden_with_block() {
    let dirs = Dirs::new();
    configure(
        &dirs.home,
        json!({ "seedingPolicy": { "default": "allow", "scope": "all" } }),
    );
    // Both made by another identity, so that the routing table's entries
    // for this one's are the service's node's alone. Imported, each is
    // seeded explicitly; the second is then unseeded, which leaves it no
    // policy of its own.
    let seeded = fixture::repository(&dirs.home, &OTHER_SEED, "seeded");
    let unpoliced = fixture::repository(&dirs.home, &OTHER_SEED, "unpoliced");
    fixture::with_node(&dirs.home, &OTHER_SEED, |node| {
        assert!(node.unseed_repo(unpoliced).unwrap());
    });
    let written = std::fs::read(dirs.home.join("config.json")).unwrap();

    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    // Once the node has built its inventory: the explicitly seeded
    // repository is in it, the other not.
    assert!(
        eventually(Duration::from_secs(30), || inventoried(
            &dirs.home, seeded, NID
        )),
        "the node never inventoried its seeded repository"
    );
    assert!(!inventoried(&dirs.home, unpoliced, NID));
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert!(!inventoried(&dirs.home, unpoliced, NID));
    assert_eq!(
        std::fs::read(dirs.home.join("config.json")).unwrap(),
        written
    );
}

/// The newest refs announcement `nid` has stored for `rid`: its timestamp.
fn announced(home: &Path, rid: RepoId, nid: &str) -> Option<i64> {
    let db = sqlite::open(home.join("node").join("node.db")).unwrap();
    let mut stmt = db
        .prepare(
            "SELECT MAX(timestamp) FROM announcements WHERE node = ?1 AND repo = ?2 AND type = 'refs'",
        )
        .unwrap();
    stmt.bind((1, nid)).unwrap();
    stmt.bind((2, rid.urn().as_str())).unwrap();
    stmt.next().unwrap();
    stmt.read::<Option<i64>, _>(0).unwrap()
}

/// A namespace `rad.reconcile` re-signed is announced once the node runs:
/// heartwood's start queues a refs announcement for each seeded repository
/// whose signed refs changed while it was stopped (0008, "Reconciliation").
#[test]
fn a_re_signed_repository_is_announced_as_the_node_starts() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &SEED, "announce");
    let before = announced(&dirs.home, rid, NID);
    fixture::unsigned_ref(&dirs.home, rid, NID);
    fixture::mark(&dirs.home, &[NID]);

    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    radicled.call("rad.identity", sealed_to(&hello, &SEED));
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert_eq!(
        reconciled["result"]["repaired"]["resigned"], 1,
        "{reconciled}"
    );
    let started = radicled.call("rad.start", json!({ "alias": "x" }));
    assert!(started["result"].is_object(), "{started}");
    assert!(
        eventually(Duration::from_secs(30), || announced(&dirs.home, rid, NID)
            > before),
        "no new refs announcement for the re-signed repository (before: {before:?})"
    );
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}
