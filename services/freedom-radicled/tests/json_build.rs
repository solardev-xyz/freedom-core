//! A JSON read's build reservation through the real binary (design 0008,
//! "Pools and budgets" and "JSON results"; review of #277, round 3): its
//! walk's items and loads, both held at once, within the one 32 MiB, half
//! for each; and a blob read as JSON's libgit2 bytes reserved with it.
//!
//! Apart from tests/reads.rs, whose own heavy reads would otherwise run
//! beside this file's large trees: cargo runs one test binary at a time.
//! `FREEDOM_RADICLED_TEST_BUDGET` shrinks the output budget
//! (src/testhooks.rs). Every node here reaches no one, as in
//! tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use common::fixture;
use common::*;
use libradicle::{BINDING_READ_BUDGET, Bounds, json};
use radicle::git::raw as git2;
use radicle::prelude::RepoId;
use serde_json::{Value, json};

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or_default()
}

fn served(dirs: &Dirs, extra: &[(&str, &str)]) -> Radicled {
    let mut radicled = Radicled::serve(dirs, extra);
    let started = radicled.start();
    assert!(started["result"].is_object(), "{started}");
    radicled
}

/// `rad.shutdown`, then a clean stop: exit 0 and the marker cleared.
fn shut_down(radicled: &mut Radicled, home: &Path) {
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(home), None);
}

/// One result as the add-on returns it.
fn text(write: impl FnOnce(&mut Vec<u8>) -> json::Written) -> String {
    json::to_string(write)
}

/// The served body of `op`, as text.
fn read_text(radicled: &mut Radicled, op: &str, args: &Value) -> String {
    match radicled.read(op, args.clone()) {
        Ok(bytes) => String::from_utf8(bytes).unwrap(),
        Err(reply) => panic!("{op} {args}: {reply}"),
    }
}

/// A repository with a README, for the blob reads.
const README: &[(&str, &[u8])] = &[("README.md", b"# Beside\n")];

/// The header sizes of `oids` in `rid`'s storage in `home`.
fn sizes(home: &Path, rid: RepoId, oids: &[git2::Oid]) -> Vec<u64> {
    let repo = git2::Repository::open_bare(fixture::storage_of(home, rid)).unwrap();
    let odb = repo.odb().unwrap();
    oids.iter()
        .map(|&oid| odb.read_header(oid).unwrap().0 as u64)
        .collect()
}

/// 0008, "Pools and budgets" and "JSON results" (review of #277, round 3):
/// a walk can hold what it has loaded and what it has built at once
/// (`tree_at` keeps its tree while it builds the entries), so a JSON read's
/// one 32 MiB reservation for its build gives its walk half for each, the
/// add-on's 16 MiB of items and 16 MiB of loads. Under a root tree of
/// 118,000 files:
/// - **both near their caps at once:** `tree_at` of a directory with a
///   4,000-byte name and 3,600 files is charged more than 12 MiB of loads
///   (what libgit2 holds of the commit, the root and the directory, from
///   their headers) and builds more than 12 MiB of items (its JSON):
///   together more than either half, and within the reservation. Served,
///   the add-on's bytes;
/// - **items past their half:** the same with 4,600 files builds more than
///   16 MiB, under its loads' half, and within 32 MiB in all: `too_large`
///   at the items' 16 MiB, as the add-on;
/// - **loads past their half:** a directory of 35,000 files is charged more
///   than 16 MiB of loads with the root, under 32 MiB: `too_large` with
///   that charge over 16 MiB, as the add-on.
#[test]
fn a_walks_loads_and_items_share_its_build_reservation() {
    const HALF: u64 = BINDING_READ_BUDGET;
    const BUILT: u64 = 2 * HALF;
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let near = "a".repeat(4000);
    let past = "b".repeat(4000);
    let (rid, revision) = fixture::repository_with_trees(
        &dirs.home,
        &SEED,
        "trees",
        118_000,
        &[(&near, 3_600), (&past, 4_600), ("c", 35_000)],
    );
    // The walk's loads to each directory, as libradicle charges them.
    let loads = {
        let repo = git2::Repository::open_bare(fixture::storage_of(&dirs.home, rid)).unwrap();
        let commit = repo
            .find_commit(git2::Oid::from_str(&revision).unwrap())
            .unwrap();
        let root = repo.find_tree(commit.tree_id()).unwrap();
        let mut ids = vec![commit.id(), root.id()];
        for dir in [near.as_str(), past.as_str(), "c"] {
            ids.push(root.get_name(dir).unwrap().id());
        }
        let s = sizes(&dirs.home, rid, &ids);
        let above = libradicle::commit_held(s[0]) + libradicle::tree_held(s[1]);
        [2, 3, 4].map(|i| above + libradicle::tree_held(s[i]))
    };
    // The add-on's answers for the two that fit its bounds, and the JSON
    // the second would build.
    let (near_json, past_json) = fixture::with_node(&dirs.home, &SEED, |node| {
        let json_of = |path: &str| {
            let (entries, commit) = node.tree_at(rid, &revision, path).unwrap();
            text(|w| json::tree_at(w, &entries, &commit))
        };
        let near_json = json_of(&near);
        assert_eq!(
            node.tree_at_bounded(rid, &revision, &near, &Bounds::for_binding())
                .map(|(e, c)| text(|w| json::tree_at(w, &e, &c)))
                .unwrap(),
            near_json
        );
        (near_json, json_of(&past).len() as u64)
    });
    let near_items = near_json.len() as u64;
    assert!(loads[0] > 12 << 20 && loads[0] <= HALF, "{}", loads[0]);
    assert!(near_items > 12 << 20 && near_items <= HALF, "{near_items}");
    assert!(loads[0] + near_items > HALF && loads[0] + near_items <= BUILT);
    assert!(past_json > HALF && loads[1] <= HALF && loads[1] + past_json <= BUILT);
    assert!(loads[2] > HALF && loads[2] <= BUILT, "{}", loads[2]);

    let mut radicled = served(&dirs, &[]);
    let at = |path: &str| json!({ "rid": rid.to_string(), "revision": revision, "path": path });
    assert_eq!(read_text(&mut radicled, "tree_at", &at(&near)), near_json);
    let reply = radicled.read("tree_at", at(&past)).unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(
        message.ends_with(&format!(" bytes is over the limit of {HALF}")),
        "{message}"
    );
    let reply = radicled.read("tree_at", at("c")).unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!("{} bytes is over the limit of {HALF}", loads[2])
    );
    shut_down(&mut radicled, &dirs.home);
}

/// 0008, "Pools and budgets" (review of #277, round 3): a blob read as JSON
/// holds, while it loads, libgit2's buffer of up to 16 MiB with its NUL and
/// structs and libradicle's copy: the build's 32 MiB and 257 bytes, one
/// reservation. With an output budget a byte short of it, `blob`,
/// `blob_at` and `readme_at` are `too_large` at once, naming it.
#[test]
fn a_blob_as_json_reserves_libgit2s_bytes_with_its_build() {
    const BUILT: u64 = 32 << 20;
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, commits) = fixture::repository_with(&dirs.home, &SEED, "beside", &[README]);
    let reserved = BUILT + libradicle::raw_held(0);
    let budget = (reserved - 1).to_string();
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_BUDGET", &budget)]);
    let r = rid.to_string();
    for (op, args) in [
        ("blob", json!({ "rid": r, "path": "README.md" })),
        (
            "blob_at",
            json!({ "rid": r, "revision": commits[0], "path": "README.md" }),
        ),
        ("readme_at", json!({ "rid": r, "revision": commits[0] })),
    ] {
        let reply = radicled.read(op, args).unwrap_err();
        assert_eq!(code(&reply), "too_large", "{op}: {reply}");
        assert_eq!(
            reply["error"]["message"],
            format!("{reserved} bytes is over the limit of {}", reserved - 1),
            "{op}"
        );
    }
    shut_down(&mut radicled, &dirs.home);
}
