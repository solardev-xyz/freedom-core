//! The identity document's cap through the real binary (design 0008's
//! deviation `identity-cap`): every read that parses a repository's
//! identity document refuses one whose blob is over 1 MiB, from the blob's
//! size, before anything parses it, with a fixed `too_large`; one of
//! exactly 1 MiB is served.
//!
//! The documents are written straight into storage before the service
//! starts, each a commit after the identity's head at `refs/rad/id`
//! (`fixture::set_identity_document`): the repository's own document with
//! a padding payload, as heartwood accepts any payload, to the byte; and
//! one past the cap that isn't JSON at all, which only a check before the
//! parse can refuse as too large. Every node here reaches no one, as in
//! tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use common::fixture;
use common::*;
use libradicle::{Bounds, json};
use radicle::prelude::RepoId;
use serde_json::{Value, json};

/// The cap: 1 MiB, the document blob's size.
const DOCUMENT: usize = 1 << 20;

/// The fixed answer past it.
const OVER: &str = "the repository's identity document is over 1 MiB";

fn served(dirs: &Dirs) -> Radicled {
    let mut radicled = Radicled::serve(dirs, &[]);
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

/// A valid identity document of exactly `size` bytes: `base`, a
/// repository's own, with a payload `xyz.freedom.padding` whose string
/// makes up the rest.
fn padded(base: &[u8], size: usize) -> Vec<u8> {
    let mut doc: Value = serde_json::from_slice(base).unwrap();
    doc["payload"]["xyz.freedom.padding"] = json!("");
    let empty = serde_json::to_vec(&doc).unwrap().len();
    doc["payload"]["xyz.freedom.padding"] = json!("z".repeat(size - empty));
    let bytes = serde_json::to_vec(&doc).unwrap();
    assert_eq!(bytes.len(), size);
    bytes
}

/// A repository with one commit; its RID and that commit's ID.
fn repository(home: &Path, name: &str) -> (RepoId, String) {
    let files: &[(&str, &[u8])] = &[("README.md", b"# Identity\n")];
    let (rid, commits) = fixture::repository_with(home, &SEED, name, &[files]);
    (rid, commits[0].clone())
}

/// `reply`'s error, if it is `too_large` with the fixed text.
fn is_over(reply: &Result<Vec<u8>, Value>) -> bool {
    match reply {
        Err(reply) => reply["error"] == json!({ "code": "too_large", "message": OVER }),
        Ok(_) => false,
    }
}

/// 0008, "Errors" and deviation `identity-cap`: three repositories, whose
/// documents are exactly 1 MiB (`at`), one byte more (`over`), and one
/// byte more that isn't JSON (`unparsed`).
/// - The reads of one repository that parse its document, `repo_info`,
///   `remotes`, `repo_stats` and `repo_meta`: `at` served, as the add-on
///   reads it; `over` and `unparsed` refused, `too_large` with the fixed
///   text, `unparsed` too, so before any parse.
/// - `tree` and `blob` without a revision parse it only when `HEAD`
///   doesn't resolve: `at`'s and `unparsed`'s don't, `over`'s does. `at`
///   and `over` served; `unparsed` refused.
/// - The listings parse every seeded repository's: refused while `over` or
///   `unparsed` is seeded; once both are unseeded, served, `at` alone.
#[test]
fn an_identity_document_over_1_mib_is_refused_before_it_is_parsed() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (at, at_commit) = repository(&dirs.home, "at");
    let (over, over_commit) = repository(&dirs.home, "over");
    let (unparsed, unparsed_commit) = repository(&dirs.home, "unparsed");
    let base = fixture::identity_document(&dirs.home, at);
    fixture::set_identity_document(&dirs.home, at, &padded(&base, DOCUMENT));
    let base = fixture::identity_document(&dirs.home, over);
    fixture::set_identity_document(&dirs.home, over, &padded(&base, DOCUMENT + 1));
    fixture::set_identity_document(&dirs.home, unparsed, &vec![b'z'; DOCUMENT + 1]);
    assert_eq!(fixture::identity_document(&dirs.home, at).len(), DOCUMENT);
    fixture::dangling_head(&dirs.home, at);
    fixture::dangling_head(&dirs.home, unparsed);

    // The add-on's answers for `at`, on the same home.
    let (info, tree) = fixture::with_node(&dirs.home, &SEED, |node| {
        let b = Bounds::for_binding;
        let info = node.repo_info_bounded(at, &b()).unwrap();
        let tree = node.tree_bounded(at, "", &b()).unwrap();
        (
            json::to_string(|w| json::repo_info(w, &info)),
            json::to_string(|w| json::tree(w, &tree)),
        )
    });

    let mut radicled = served(&dirs);
    let one = |rid: RepoId, commit: &str| {
        let r = rid.to_string();
        [
            ("repo_info", json!({ "rid": r })),
            ("remotes", json!({ "rid": r })),
            ("repo_stats", json!({ "rid": r, "revision": commit })),
            ("repo_meta", json!({ "rid": r })),
        ]
    };
    for (op, args) in one(at, &at_commit) {
        let reply = radicled.read(op, args.clone());
        assert!(reply.is_ok(), "{op} {args}: {reply:?}");
    }
    let answer = radicled.read("repo_info", json!({ "rid": at.to_string() }));
    assert_eq!(String::from_utf8(answer.unwrap()).unwrap(), info);
    for (rid, commit) in [(over, &over_commit), (unparsed, &unparsed_commit)] {
        for (op, args) in one(rid, commit) {
            let reply = radicled.read(op, args.clone());
            assert!(is_over(&reply), "{op} {args}: {reply:?}");
        }
    }

    // Without a revision.
    let headless = |rid: RepoId| {
        let r = rid.to_string();
        [
            ("tree", json!({ "rid": r, "path": "" })),
            ("blob", json!({ "rid": r, "path": "README.md" })),
        ]
    };
    for rid in [at, over] {
        for (op, args) in headless(rid) {
            let reply = radicled.read(op, args.clone());
            assert!(reply.is_ok(), "{op} {args}: {reply:?}");
        }
    }
    let answer = radicled.read("tree", json!({ "rid": at.to_string(), "path": "" }));
    assert_eq!(String::from_utf8(answer.unwrap()).unwrap(), tree);
    for (op, args) in headless(unparsed) {
        let reply = radicled.read(op, args.clone());
        assert!(is_over(&reply), "{op} {args}: {reply:?}");
    }

    // The listings.
    let listings = ["list_repos", "list_seeded_repos", "repos_meta"];
    for op in listings {
        let reply = radicled.read(op, Value::Null);
        assert!(is_over(&reply), "{op}: {reply:?}");
    }
    let node_info = radicled.read("node_info", Value::Null).unwrap();
    let node_info: Value = serde_json::from_slice(&node_info).unwrap();
    assert_eq!(node_info["repos_total"], Value::Null, "{node_info}");
    assert_eq!(node_info["repos_error"], OVER, "{node_info}");

    // `over` unseeded: `unparsed` still refuses them; then both.
    for (rid, refused) in [(over, true), (unparsed, false)] {
        let reply = radicled.call("rad.unseed", json!({ "rid": rid.to_string() }));
        assert_eq!(reply["result"], json!({ "unseeded": true }), "{reply}");
        for op in listings {
            let reply = radicled.read(op, Value::Null);
            assert_eq!(is_over(&reply), refused, "{op}: {reply:?}");
        }
    }
    let listed: Value =
        serde_json::from_slice(&radicled.read("list_repos", Value::Null).unwrap()).unwrap();
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0]["rid"], at.to_string(), "{listed:?}");
    let node_info = radicled.read("node_info", Value::Null).unwrap();
    let node_info: Value = serde_json::from_slice(&node_info).unwrap();
    assert_eq!(node_info["repos_total"], 1, "{node_info}");

    shut_down(&mut radicled, &dirs.home);
}
