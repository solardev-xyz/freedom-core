//! `rad.reconcile` through the real binary (design 0008, "Reconciliation"
//! and "Tests first": "The dirty marker", "Reconciliation", "a dirty home
//! across an identity's loss"): the marker around the run, the repairs on
//! homes libradicle made, and the endings that end the process.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::fixture::{self, OTHER_SEED};
use common::*;
use serde_json::{Value, json};

/// A process for `dirs`, through `rad.identity` with `seed`'s key, or a
/// throwaway one for `None`.
fn identified(dirs: &Dirs, seed: Option<&[u8; 32]>, extra: &[(&str, &str)]) -> Radicled {
    let mut radicled = Radicled::serve(dirs, extra);
    let hello = radicled.hello();
    let params = match seed {
        Some(seed) => sealed_to(&hello, seed),
        None => json!({ "ephemeral": true }),
    };
    let identity = radicled.call("rad.identity", params);
    assert!(identity["result"].is_object(), "{identity}");
    radicled
}

fn reconcile(radicled: &mut Radicled) -> Value {
    radicled.call("rad.reconcile", json!({}))
}

fn repaired(reply: &Value, what: &str) -> u64 {
    reply["result"]["repaired"][what].as_u64().unwrap()
}

/// `reply`, and what the quarantine record says, for a failing assertion.
fn context(reply: &Value, dirs: &Dirs) -> String {
    format!("{reply}; quarantined: {}", fixture::evidence(&dirs.home))
}

#[test]
fn a_clean_home_reconciles_and_is_marked_for_the_run() {
    let dirs = Dirs::new();
    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(
        reply["result"],
        json!({
            "was_dirty": false,
            "repaired": {
                "clones": 0, "left": 0, "locks": 0, "namespaces": 0,
                "resigned": 0, "caches": 0, "quarantined": 0,
            },
            "quarantined": { "count": 0, "first": [] },
        }),
        "{reply}"
    );
    // Present for the whole run, naming the running identity.
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
    // Once only: a second is invalid, and ends the process.
    let again = reconcile(&mut radicled);
    assert_eq!(again["error"]["code"], "invalid_argument", "{again}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn reconcile_takes_no_params() {
    let dirs = Dirs::new();
    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = radicled.call("rad.reconcile", json!({ "full": true }));
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), None);
}

#[test]
fn temporary_clones_are_removed_and_lookalikes_left() {
    let dirs = Dirs::new();
    let rid = fixture::repository(&dirs.home, &SEED, "clones");
    let storage = dirs.home.join("storage");
    // A first clone, killed before its rename.
    let clone = storage.join(format!("{}.tmp", rid.canonical()));
    std::fs::create_dir_all(clone.join("objects")).unwrap();
    std::fs::write(clone.join("HEAD"), "ref: refs/heads/master\n").unwrap();
    // A name with an extension that isn't a clone's.
    let other = storage.join("notes.txt");
    std::fs::write(&other, "left alone").unwrap();
    // A link with a clone's name: never followed, never removed.
    #[cfg(unix)]
    let link = {
        let target = dirs.home.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("kept"), "kept").unwrap();
        let link = storage.join(format!("{}.lock", rid.canonical()));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        (link, target)
    };

    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(repaired(&reply, "clones"), 1, "{}", context(&reply, &dirs));
    assert!(!clone.exists());
    assert!(other.exists());
    assert!(fixture::storage_of(&dirs.home, rid).is_dir());
    #[cfg(unix)]
    {
        assert_eq!(repaired(&reply, "left"), 2, "{}", context(&reply, &dirs));
        assert!(link.0.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(link.1.join("kept").exists());
    }
    #[cfg(not(unix))]
    assert_eq!(repaired(&reply, "left"), 1, "{}", context(&reply, &dirs));
}

/// A kill between a COB's ref and its `rad/sigrefs`, then a start as the
/// same identity: its namespace is re-signed, and its cache rebuilt.
#[test]
fn the_running_identitys_stale_namespace_is_resigned() {
    let dirs = Dirs::new();
    let rid = fixture::repository(&dirs.home, &SEED, "resign");
    fixture::unsigned_ref(&dirs.home, rid, NID);
    fixture::mark(&dirs.home, &[NID]);
    let before = fixture::sigrefs(&dirs.home, rid, NID);

    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    let result = &reply["result"];
    assert_eq!(result["was_dirty"], true, "{reply}");
    assert_eq!(
        repaired(&reply, "resigned"),
        1,
        "{}",
        context(&reply, &dirs)
    );
    assert_eq!(repaired(&reply, "caches"), 1, "{}", context(&reply, &dirs));
    assert_eq!(
        result["quarantined"]["count"],
        0,
        "{}",
        context(&reply, &dirs)
    );
    assert_ne!(fixture::sigrefs(&dirs.home, rid, NID), before);
    assert!(fixture::has_unsigned_ref(&dirs.home, rid, NID));
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// The same kill, then a start under another key: the namespace is checked,
/// never signed, and its repository quarantined with every byte kept. The
/// marker then names only the running identity.
#[test]
fn another_identitys_stale_namespace_is_quarantined_and_kept() {
    for seed in [Some(&OTHER_SEED), None] {
        let dirs = Dirs::new();
        let rid = fixture::repository(&dirs.home, &SEED, "quarantine");
        fixture::unsigned_ref(&dirs.home, rid, NID);
        fixture::mark(&dirs.home, &[NID]);
        let before = fixture::sigrefs(&dirs.home, rid, NID);

        let mut radicled = identified(&dirs, seed, &[]);
        let reply = reconcile(&mut radicled);
        let result = &reply["result"];
        assert_eq!(result["was_dirty"], true, "{reply}");
        assert_eq!(
            repaired(&reply, "resigned"),
            0,
            "{}",
            context(&reply, &dirs)
        );
        assert_eq!(
            repaired(&reply, "quarantined"),
            1,
            "{}",
            context(&reply, &dirs)
        );
        assert_eq!(
            result["quarantined"]["count"],
            1,
            "{}",
            context(&reply, &dirs)
        );
        let entry = &result["quarantined"]["first"][0];
        assert_eq!(entry["rid"], rid.to_string(), "{reply}");
        assert_eq!(entry["kind"], "namespace", "{reply}");
        assert_eq!(entry["qid"].as_str().unwrap().len(), 32, "{reply}");
        assert!(entry["since"].as_u64().unwrap() > 0, "{reply}");
        assert!(entry.get("evidence").is_none(), "{reply}");
        // Nothing signed, nothing deleted.
        assert_eq!(fixture::sigrefs(&dirs.home, rid, NID), before);
        assert!(fixture::has_unsigned_ref(&dirs.home, rid, NID));
        let named = match seed {
            Some(seed) => vec![fixture::nid_of(seed)],
            // A throwaway key isn't named: it owns no namespace.
            None => vec![],
        };
        assert_eq!(fixture::marked(&dirs.home), Some(named));
        assert!(!dirs.home.join("keys").join("radicle").exists());
    }
}

/// The cutoff: `deadline`, and the process ends, with the marker and the
/// progress kept; a retry in a new process finishes.
#[test]
fn the_cutoff_answers_deadline_and_a_retry_finishes() {
    let cutoff = [("FREEDOM_RADICLED_TEST_RECONCILE_CUTOFF_MS", "0")];
    // On a clean home the marker is written before anything else, so a run
    // cut off before its first unit leaves it.
    let dirs = Dirs::new();
    fixture::repository(&dirs.home, &SEED, "clean");
    let mut radicled = identified(&dirs, Some(&SEED), &cutoff);
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    let dirs = Dirs::new();
    let rid = fixture::repository(&dirs.home, &SEED, "cutoff");
    fixture::unsigned_ref(&dirs.home, rid, NID);
    fixture::mark(&dirs.home, &[NID]);

    let mut radicled = identified(&dirs, Some(&SEED), &cutoff);
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["result"]["was_dirty"], true, "{reply}");
    assert_eq!(
        repaired(&reply, "resigned"),
        1,
        "{}",
        context(&reply, &dirs)
    );
}

/// A failure outside any one repository: `recovery_failed`, naming the
/// step, and nothing deleted.
#[test]
fn an_unreadable_cache_database_is_recovery_failed_with_nothing_deleted() {
    let dirs = Dirs::new();
    let rid = fixture::repository(&dirs.home, &SEED, "unreadable");
    let db = dirs.home.join("cobs").join("cache.db");
    for sidecar in ["cache.db-wal", "cache.db-shm"] {
        let _ = std::fs::remove_file(dirs.home.join("cobs").join(sidecar));
    }
    let garbage = vec![0xa5u8; 8192];
    std::fs::write(&db, &garbage).unwrap();

    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["error"]["code"], "recovery_failed", "{reply}");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.starts_with("the reconcile state"), "{reply}");
    assert!(!message.contains(dirs.home.to_str().unwrap()), "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(std::fs::read(&db).unwrap(), garbage);
    assert!(fixture::storage_of(&dirs.home, rid).is_dir());
}

#[test]
fn an_unreadable_marker_is_recovery_failed_and_left() {
    let dirs = Dirs::new();
    std::fs::create_dir_all(dirs.home.join("node")).unwrap();
    let marker = dirs.home.join("node").join("dirty");
    std::fs::write(&marker, b"{not json").unwrap();

    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["error"]["code"], "recovery_failed", "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("the dirty marker"),
        "{reply}"
    );
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(std::fs::read(&marker).unwrap(), b"{not json");
}

/// A throwaway key between runs of the real one (0008, "successive
/// throwaway keys" and "with A's vault kept or restored"): a throwaway run
/// names no one, and loses no name, so the real key's next run checks its
/// own namespace and re-signs it.
#[test]
fn a_throwaway_run_keeps_the_real_identitys_name_for_its_next_run() {
    let dirs = Dirs::new();
    let rid = fixture::repository(&dirs.home, &SEED, "throwaway");

    // A clean home, then a throwaway run: present for the run, naming no
    // one.
    let mut radicled = identified(&dirs, None, &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["result"]["was_dirty"], false, "{reply}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![]));
    drop(radicled);

    // The real key next: the marker was present, so the full repair runs,
    // and the marker names it.
    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["result"]["was_dirty"], true, "{reply}");
    assert_eq!(
        reply["result"]["quarantined"]["count"],
        0,
        "{}",
        context(&reply, &dirs)
    );
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
    drop(radicled);

    // The real key killed between a ref and its sigrefs, then a throwaway
    // run cut off before its first unit: the marker still names the real
    // identity, and nothing is quarantined.
    fixture::unsigned_ref(&dirs.home, rid, NID);
    let before = fixture::sigrefs(&dirs.home, rid, NID);
    let mut radicled = identified(
        &dirs,
        None,
        &[("FREEDOM_RADICLED_TEST_RECONCILE_CUTOFF_MS", "0")],
    );
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    // The real key again: its namespace is re-signed, with its own key.
    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(
        repaired(&reply, "resigned"),
        1,
        "{}",
        context(&reply, &dirs)
    );
    assert_eq!(
        reply["result"]["quarantined"]["count"],
        0,
        "{}",
        context(&reply, &dirs)
    );
    assert_ne!(fixture::sigrefs(&dirs.home, rid, NID), before);
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// The process starts, `main`'s checked
/// `libradicle::isolate_git_config_single_threaded` finding one thread, and
/// reconciliation runs with the token it returned: the repository's open
/// reads no git configuration outside the repository. A malformed
/// `.gitconfig` and XDG configuration in the service's `HOME` would fail
/// the open, and quarantine the repository at its unit's `begin`.
#[test]
fn reconciliation_reads_no_git_configuration_from_home() {
    let dirs = Dirs::new();
    fixture::repository(&dirs.home, &SEED, "no-config");
    // Dirty, so that the full repair opens the repository.
    fixture::mark(&dirs.home, &[NID]);
    let malformed = "[user\n\tname = unterminated\n";
    std::fs::write(dirs.own_home.join(".gitconfig"), malformed).unwrap();
    let xdg = dirs.own_home.join(".config").join("git");
    std::fs::create_dir_all(&xdg).unwrap();
    std::fs::write(xdg.join("config"), malformed).unwrap();

    let mut radicled = identified(&dirs, Some(&SEED), &[]);
    let reply = reconcile(&mut radicled);
    assert_eq!(reply["result"]["was_dirty"], true, "{reply}");
    assert_eq!(
        reply["result"]["quarantined"]["count"],
        0,
        "{}",
        context(&reply, &dirs)
    );
    assert_eq!(
        repaired(&reply, "quarantined"),
        0,
        "{}",
        context(&reply, &dirs)
    );
}
