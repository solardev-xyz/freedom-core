//! `rad.read`'s pass-through ops through the real binary (design 0008,
//! "Methods", "Deadlines", "Errors", "Pools and budgets", "JSON results"
//! and "Tests first"): each op answers a head and the add-on's exact bytes
//! as a body stream, under credit; past a cap a read is `too_large`, its
//! reply and never its stream's abort; a read waiting for the output budget
//! ends at its cancel and its deadline; a quarantined or repairing
//! repository is refused as 0008 says; and a commit whose diff isn't UTF-8
//! is served, decoded lossily (libradicle #31).
//!
//! The add-on's bytes are libradicle's serializers over its bounded reads,
//! as the add-on calls them, on the same home before the service starts.
//! `FREEDOM_RADICLED_TEST_BUDGET` shrinks the output budget,
//! `FREEDOM_RADICLED_TEST_HOLD_WRITE` holds a write past its start and
//! `FREEDOM_RADICLED_TEST_HOLD_REPAIR` each repair turn (src/testhooks.rs).
//! Every node here reaches no one, as in tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::fixture;
use common::*;
use libradicle::{BINDING_READ_BUDGET, Blob, Bounds, json};
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::quarantine::Kind;
use serde_json::{Value, json};

/// A third identity, who makes the repositories the quarantine test reads.
const CREATOR: [u8; 32] = [9; 32];

/// 32 MiB: the most JSON a read writes.
const JSON_CAP: usize = 32 << 20;

/// 16 MiB: the largest blob a read serves as JSON.
const BLOB_CAP: usize = 16 << 20;

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
fn shut_down(radicled: &mut Radicled, home: &Path) -> String {
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(home), None);
    log
}

/// One result as the add-on returns it.
fn text(write: impl FnOnce(&mut Vec<u8>) -> json::Written) -> String {
    json::to_string(write)
}

/// The code today's message test gives a libradicle message.
fn todays(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("not found") || lower.contains("does not exist") || lower.contains("notfound")
    {
        "not_found"
    } else {
        "failed"
    }
}

/// The served body of `op`, as text.
fn read_text(radicled: &mut Radicled, op: &str, args: &Value) -> String {
    match radicled.read(op, args.clone()) {
        Ok(bytes) => String::from_utf8(bytes).unwrap(),
        Err(reply) => panic!("{op} {args}: {reply}"),
    }
}

/// The repository the pass-through test reads: two commits, the second
/// with Latin-1 text, a non-UTF-8 diff, escapes and a binary file.
const FIRST: &[(&str, &[u8])] = &[
    ("README.md", b"# Reads\n"),
    ("src/lib.rs", b"pub fn read() {}\n"),
    ("docs/guide.md", b"A guide.\n"),
];
const SECOND: &[(&str, &[u8])] = &[
    ("README.md", b"# Reads\n\nMore.\n"),
    ("src/lib.rs", b"// caf\xe9\npub fn read() {}\n"),
    ("latin1.txt", b"caf\xe9 cr\xe8me\n"),
    ("quotes.txt", b"\"quoted\" \\ back\tslash\n"),
    ("image.bin", b"\x00\x01\x02PNG\r\n"),
];

/// 0008, "Methods" and "Parity": each pass-through op answers a head
/// `{ content_type, bytes }` and the add-on's exact JSON as its body, with
/// today's arguments. A commit whose diff isn't UTF-8 is served, its text
/// decoded lossily (R-19). libradicle's errors are `not_found` by today's
/// message test, otherwise `failed`, with its message; what doesn't parse
/// is `invalid_argument`.
#[test]
fn each_pass_through_op_answers_the_add_ons_bytes() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, commits) = fixture::repository_with(&dirs.home, &SEED, "reads", &[FIRST, SECOND]);
    let r = rid.to_string();
    let (first, second) = (commits[0].clone(), commits[1].clone());
    let missing_rid: RepoId = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap();
    // Seeded, but not yet fetched: listed as seeded, not as stored.
    {
        let db = sqlite::open(dirs.home.join("node").join("policies.db")).unwrap();
        let mut stmt = db
            .prepare("INSERT INTO seeding (id, scope, policy) VALUES (?1, 'all', 'allow')")
            .unwrap();
        stmt.bind((1, missing_rid.to_string().as_str())).unwrap();
        stmt.next().unwrap();
    }
    let absent = "0".repeat(40);

    // The add-on's answers, on the same home.
    let (expected, errors) = fixture::with_node(&dirs.home, &SEED, |node| {
        let b = Bounds::for_binding;
        let blob_at = |node: &libradicle::Embedded, revision: &str, path: &str| {
            let blob = node
                .read_blob_at_capped(rid, revision, path, BINDING_READ_BUDGET)
                .unwrap();
            text(|w| json::blob(w, path, &blob))
        };
        let tree_at = |node: &libradicle::Embedded, revision: &str, path: &str| {
            let (entries, commit) = node.tree_at_bounded(rid, revision, path, &b()).unwrap();
            text(|w| json::tree_at(w, &entries, &commit))
        };
        let commits_page = |node: &libradicle::Embedded, page, per_page| {
            let commits = node
                .commits_bounded(rid, &second, page, per_page, &b())
                .unwrap();
            text(|w| json::commits(w, &commits))
        };
        let commit = |node: &libradicle::Embedded, revision: &str| {
            let detail = node.commit_bounded(rid, revision, &b()).unwrap();
            text(|w| json::commit(w, &detail))
        };
        let expected = vec![
            (
                "repo_info",
                json!({ "rid": r }),
                text(|w| json::repo_info(w, &node.repo_info_bounded(rid, &b()).unwrap())),
            ),
            (
                "tree",
                json!({ "rid": r, "path": "" }),
                text(|w| json::tree(w, &node.tree_bounded(rid, "", &b()).unwrap())),
            ),
            (
                "tree",
                json!({ "rid": r, "path": "src" }),
                text(|w| json::tree(w, &node.tree_bounded(rid, "src", &b()).unwrap())),
            ),
            (
                "tree_at",
                json!({ "rid": r, "revision": first, "path": "" }),
                tree_at(node, &first, ""),
            ),
            (
                "tree_at",
                json!({ "rid": r, "revision": second, "path": "docs" }),
                tree_at(node, &second, "docs"),
            ),
            (
                "blob",
                json!({ "rid": r, "path": "README.md" }),
                text(|w| {
                    let blob = node
                        .read_blob_capped(rid, "README.md", BINDING_READ_BUDGET)
                        .unwrap();
                    json::blob(w, "README.md", &blob)
                }),
            ),
            (
                "blob_at",
                json!({ "rid": r, "revision": first, "path": "README.md" }),
                blob_at(node, &first, "README.md"),
            ),
            (
                "blob_at",
                json!({ "rid": r, "revision": second, "path": "docs/guide.md" }),
                blob_at(node, &second, "docs/guide.md"),
            ),
            (
                "blob_at",
                json!({ "rid": r, "revision": second, "path": "latin1.txt" }),
                blob_at(node, &second, "latin1.txt"),
            ),
            (
                "blob_at",
                json!({ "rid": r, "revision": second, "path": "quotes.txt" }),
                blob_at(node, &second, "quotes.txt"),
            ),
            (
                "blob_at",
                json!({ "rid": r, "revision": second, "path": "image.bin" }),
                blob_at(node, &second, "image.bin"),
            ),
            (
                "commits",
                json!({ "rid": r, "parent": second, "page": 0, "per_page": 30 }),
                commits_page(node, 0, 30),
            ),
            (
                "commits",
                json!({ "rid": r, "parent": second, "page": 1, "per_page": 1 }),
                commits_page(node, 1, 1),
            ),
            (
                "commits",
                json!({ "rid": r, "parent": second, "page": 0, "per_page": 0 }),
                commits_page(node, 0, 0),
            ),
            (
                "commit",
                json!({ "rid": r, "revision": second }),
                commit(node, &second),
            ),
            (
                "commit",
                json!({ "rid": r, "revision": first }),
                commit(node, &first),
            ),
            (
                "issues",
                json!({ "rid": r }),
                text(|w| json::issues(w, &node.issues_bounded(rid, &b()).unwrap())),
            ),
            (
                "patches",
                json!({ "rid": r }),
                text(|w| json::patches(w, &node.patches_bounded(rid, &b()).unwrap())),
            ),
            (
                "list_repos",
                json!({}),
                text(|w| json::repos(w, &node.list_repos_bounded(&b()).unwrap())),
            ),
            (
                "list_seeded_repos",
                Value::Null,
                text(|w| json::seeded_repos(w, &node.list_seeded_repos_bounded(&b()).unwrap())),
            ),
            (
                "identity",
                json!({}),
                text(|w| json::identity(w, &node.identity())),
            ),
            (
                "status",
                json!({}),
                text(|w| json::connected_peers(w, node.connected_peers().unwrap())),
            ),
            (
                "seeders",
                json!({ "rid": r }),
                text(|w| json::seeding(w, node.seeders(rid).unwrap())),
            ),
        ];
        let errors = vec![
            (
                "blob_at",
                json!({ "rid": r, "revision": second, "path": "missing.txt" }),
                node.read_blob_at_capped(rid, &second, "missing.txt", BINDING_READ_BUDGET)
                    .unwrap_err()
                    .to_string(),
            ),
            (
                "blob_at",
                json!({ "rid": r, "revision": second, "path": "src" }),
                node.read_blob_at_capped(rid, &second, "src", BINDING_READ_BUDGET)
                    .unwrap_err()
                    .to_string(),
            ),
            (
                "tree_at",
                json!({ "rid": r, "revision": absent, "path": "" }),
                node.tree_at_bounded(rid, &absent, "", &b())
                    .unwrap_err()
                    .to_string(),
            ),
            (
                "repo_info",
                json!({ "rid": missing_rid.to_string() }),
                node.repo_info_bounded(missing_rid, &b())
                    .unwrap_err()
                    .to_string(),
            ),
        ];
        (expected, errors)
    });
    // The lossy decoding is what is served: the Latin-1 bytes, as U+FFFD.
    let lossy = expected
        .iter()
        .find(|(op, args, _)| *op == "commit" && args["revision"] == second.as_str())
        .unwrap();
    assert!(lossy.2.contains("caf\u{FFFD}"), "{}", lossy.2);
    let listed = |op: &str| &expected.iter().find(|(o, _, _)| *o == op).unwrap().2;
    assert_ne!(listed("list_repos"), listed("list_seeded_repos"));
    assert!(listed("list_seeded_repos").contains(&missing_rid.to_string()));
    assert!(!listed("list_repos").contains(&missing_rid.to_string()));
    assert!(errors.iter().any(|(_, _, e)| todays(e) == "not_found"));
    assert!(errors.iter().any(|(_, _, e)| todays(e) == "failed"));

    let mut radicled = served(&dirs, &[]);
    for (op, args, bytes) in &expected {
        assert_eq!(&read_text(&mut radicled, op, args), bytes, "{op} {args}");
    }
    for (op, args, message) in &errors {
        let reply = radicled.read(op, args.clone()).unwrap_err();
        assert_eq!(code(&reply), todays(message), "{op} {args}: {reply}");
        assert_eq!(reply["error"]["message"], message.as_str(), "{reply}");
    }
    // What doesn't parse.
    let reply = radicled
        .read(
            "tree_at",
            json!({ "rid": r, "revision": first.to_uppercase(), "path": "" }),
        )
        .unwrap_err();
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    let reply = radicled
        .read("list_files", json!({ "rid": r }))
        .unwrap_err();
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    let reply = radicled.call("rad.read", json!({ "args": {} }));
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    let log = shut_down(&mut radicled, &dirs.home);
    // Neither content nor libradicle's messages are logged.
    assert!(!log.contains("caf"), "{log}");
    assert!(!log.contains("missing.txt"), "{log}");
}

/// Blob content whose JSON, at `name`, is exactly `json` bytes, with `len`
/// bytes of content: `"` escapes to two bytes, `a` stays one.
fn blob_of_json(name: &str, len: usize, json: usize) -> Vec<u8> {
    let empty = Blob {
        binary: false,
        content: Vec::new(),
    };
    let around = text(|w| json::blob(w, name, &empty)).len();
    let quotes = json - around - len;
    let mut content = vec![b'a'; len - quotes];
    content.extend(std::iter::repeat_n(b'"', quotes));
    content
}

/// The bounds' repository: a blob whose JSON is exactly 32 MiB and one a
/// byte longer, both 16 MiB of content; one over 16 MiB; Latin-1 text
/// whose lossy copies pass the built budget, and some that doesn't; and
/// an 8 MiB text.
fn bounds_repository(home: &Path) -> (RepoId, String) {
    let at = blob_of_json("at.txt", BLOB_CAP, JSON_CAP);
    let over = blob_of_json("ov.txt", BLOB_CAP, JSON_CAP + 1);
    let big = vec![b'a'; BLOB_CAP + 1];
    let latin = vec![0xe9; 8 << 20];
    let latin_ok = vec![0xe9; 4 << 20];
    let half = vec![b'a'; 8 << 20];
    let files: &[(&str, &[u8])] = &[
        ("at.txt", &at),
        ("ov.txt", &over),
        ("big.txt", &big),
        ("latin.txt", &latin),
        ("latin-ok.txt", &latin_ok),
        ("half.txt", &half),
    ];
    let (rid, commits) = fixture::repository_with(home, &SEED, "bounds", &[files]);
    (rid, commits[0].clone())
}

fn blob_at(rid: RepoId, revision: &str, path: &str) -> Value {
    json!({ "rid": rid.to_string(), "revision": revision, "path": path })
}

/// 0008, "Pools and budgets", "JSON results" and "Deadlines": a read of
/// exactly 32 MiB of JSON is served, its head naming its length, in data
/// frames of at most 64 KiB under main's credit; one byte more is
/// `too_large`, as the reply. A blob over 16 MiB is `too_large` from its
/// header, and one whose lossy copies would pass the built budget is too,
/// though its JSON would fit.
#[test]
fn a_reply_at_32_mib_is_served_and_one_byte_more_is_too_large() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, revision) = bounds_repository(&dirs.home);
    let (at, latin_ok) = fixture::with_node(&dirs.home, &SEED, |node| {
        let json_of = |path: &str| {
            let blob = node
                .read_blob_at_capped(rid, &revision, path, BLOB_CAP as u64)
                .unwrap();
            text(|w| json::blob(w, path, &blob)).into_bytes()
        };
        (json_of("at.txt"), json_of("latin-ok.txt"))
    });
    assert_eq!(at.len(), JSON_CAP);

    let mut radicled = served(&dirs, &[]);
    let id = radicled.request(
        "rad.read",
        json!({ "op": "blob_at", "args": blob_at(rid, &revision, "at.txt") }),
    );
    let head = radicled.reply(id);
    assert_eq!(
        head["result"],
        json!({ "content_type": "application/json", "bytes": JSON_CAP }),
        "{head}"
    );
    let mut frames = 0;
    loop {
        let frame = radicled.stream(id);
        if frame["stream"] != "data" {
            assert_eq!(frame["stream"], "end", "{frame}");
            break;
        }
        let len = frame["len"].as_u64().unwrap();
        assert!(len > 0 && len <= 64 << 10, "{frame}");
        frames += 1;
        radicled.credit(id, u32::try_from(len).unwrap());
    }
    assert!(frames >= JSON_CAP / (64 << 10), "{frames}");
    let body = radicled.taken(id);
    assert!(
        body == at,
        "{} bytes served, {} expected",
        body.len(),
        at.len()
    );

    let reply = radicled
        .read("blob_at", blob_at(rid, &revision, "ov.txt"))
        .unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!("{} bytes is over the limit of {JSON_CAP}", JSON_CAP + 1)
    );
    let reply = radicled
        .read("blob_at", blob_at(rid, &revision, "big.txt"))
        .unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!("{} bytes is over the limit of {BLOB_CAP}", BLOB_CAP + 1)
    );
    // 8 MiB of Latin-1: its content, and two lossy copies of 24 MiB.
    let reply = radicled
        .read("blob_at", blob_at(rid, &revision, "latin.txt"))
        .unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!("{} bytes is over the limit of {JSON_CAP}", 56 << 20)
    );
    // 4 MiB of it: 28 MiB held, served lossily.
    let body = radicled
        .read("blob_at", blob_at(rid, &revision, "latin-ok.txt"))
        .unwrap();
    assert!(body == latin_ok, "{} bytes served", body.len());
    assert!(
        String::from_utf8(body)
            .unwrap()
            .contains("\u{FFFD}\u{FFFD}")
    );
    // Everything was released: the same read again.
    assert!(
        radicled
            .read("blob_at", blob_at(rid, &revision, "at.txt"))
            .is_ok()
    );
    shut_down(&mut radicled, &dirs.home);
}

/// 0008, "Pools and budgets" and "Deadlines": a read that can't reserve
/// waits, holding what it has, and ends at main's cancel and at its
/// deadline, releasing it, so a read waiting behind it goes on. A body
/// main doesn't credit holds its bytes until the stop, which ends it.
///
/// With a 65 MiB budget: a 32 MiB body, never credited past its window,
/// holds nearly 32 MiB. An 8 MiB read then reserves its build's 32 MiB
/// and waits at its JSON's steps; a small read waits for its build's.
#[test]
fn a_read_waiting_for_the_budget_ends_at_its_cancel_and_its_deadline() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, revision) = bounds_repository(&dirs.home);
    let deadline = Duration::from_secs(8);
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_BUDGET", "68157440"),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "8000"),
        ],
    );
    let held = radicled.request(
        "rad.read",
        json!({ "op": "blob_at", "args": blob_at(rid, &revision, "at.txt") }),
    );
    let head = radicled.reply(held);
    assert_eq!(head["result"]["bytes"], JSON_CAP, "{head}");
    // Its window's worth, and no credit.
    radicled.uncredited(held, 128 << 10);
    let status = |radicled: &mut Radicled| radicled.request("rad.read", json!({ "op": "status" }));

    // Main's cancel ends a wait.
    let waiting = radicled.request(
        "rad.read",
        json!({ "op": "blob_at", "args": blob_at(rid, &revision, "half.txt") }),
    );
    std::thread::sleep(Duration::from_millis(1000));
    let behind = status(&mut radicled);
    assert!(!radicled.any_within(waiting, Duration::from_millis(1500)));
    assert!(!radicled.any_within(behind, Duration::ZERO));
    radicled.cancel(waiting);
    assert_eq!(code(&radicled.reply(waiting)), "cancelled");
    assert_eq!(
        radicled.read_reply(behind).unwrap(),
        br#"{"connectedPeers":0}"#
    );

    // So does its deadline, 8 s from its admission.
    let waiting = radicled.request(
        "rad.read",
        json!({ "op": "blob_at", "args": blob_at(rid, &revision, "half.txt") }),
    );
    let admitted = Instant::now();
    std::thread::sleep(Duration::from_millis(2000));
    let behind = status(&mut radicled);
    assert!(!radicled.any_within(behind, Duration::from_millis(2000)));
    assert_eq!(code(&radicled.reply(waiting)), "deadline");
    assert!(admitted.elapsed() >= deadline);
    assert_eq!(
        radicled.read_reply(behind).unwrap(),
        br#"{"connectedPeers":0}"#
    );
    // Nothing more of it.
    assert!(!radicled.any_within(waiting, Duration::from_millis(500)));

    // The held body still waits for credit: the stop ends it, and the
    // drain is clean.
    assert!(!radicled.any_within(held, Duration::ZERO));
    shut_down(&mut radicled, &dirs.home);
}

/// 0008, "Methods" ("The repair fence") and "Errors" (`quarantined`): a
/// repository quarantined for its cache answers its COB ops `quarantined`,
/// with the record's kind and step, and its other reads; one quarantined
/// for a namespace answers every read naming it `quarantined`. The
/// listings stay as they are.
#[test]
fn a_quarantined_repository_is_refused_as_0008_says() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (cache, commits) = fixture::repository_with(&dirs.home, &CREATOR, "cache", &[FIRST]);
    let (namespace, _) = fixture::repository_with(&dirs.home, &CREATOR, "namespace", &[FIRST]);
    fixture::quarantine(&dirs.home, cache, Kind::Cache);
    fixture::quarantine(&dirs.home, namespace, Kind::Namespace);
    let mut radicled = served(&dirs, &[]);

    let args = |rid: RepoId| {
        let r = rid.to_string();
        vec![
            ("repo_info", json!({ "rid": r })),
            ("tree", json!({ "rid": r, "path": "" })),
            (
                "tree_at",
                json!({ "rid": r, "revision": commits[0], "path": "" }),
            ),
            ("blob", json!({ "rid": r, "path": "README.md" })),
            (
                "blob_at",
                json!({ "rid": r, "revision": commits[0], "path": "README.md" }),
            ),
            (
                "commits",
                json!({ "rid": r, "parent": commits[0], "page": 0, "per_page": 30 }),
            ),
            ("commit", json!({ "rid": r, "revision": commits[0] })),
            ("seeders", json!({ "rid": r })),
            ("issues", json!({ "rid": r })),
            ("patches", json!({ "rid": r })),
        ]
    };
    for (op, args) in args(cache) {
        let read = radicled.read(op, args.clone());
        if op == "issues" || op == "patches" {
            let reply = read.unwrap_err();
            assert_eq!(code(&reply), "quarantined", "{op}: {reply}");
            assert_eq!(
                reply["error"]["data"],
                json!({ "kind": "cache", "step": "namespace" }),
                "{reply}"
            );
        } else {
            assert!(read.is_ok(), "{op} {args}: {read:?}");
        }
    }
    for (op, args) in args(namespace) {
        let reply = radicled.read(op, args.clone()).unwrap_err();
        assert_eq!(code(&reply), "quarantined", "{op}: {reply}");
        assert_eq!(reply["error"]["data"]["kind"], "namespace", "{reply}");
    }
    let listed = read_text(&mut radicled, "list_repos", &json!({}));
    assert!(listed.contains(&cache.to_string()), "{listed}");
    assert!(listed.contains(&namespace.to_string()), "{listed}");
    shut_down(&mut radicled, &dirs.home);
}

const STARTED: &str = "test hook: the write has started";
const QUEUED: &str = "an online repair is queued";
const DONE: &str = "an online repair is done";

/// 0008, "Methods" ("The repair fence") and "Writes": a repository's COB
/// ops answer `stopped` while a COB write to it is past its start and not
/// yet proven, and while its online repair runs; its other reads go on.
/// Once the write is proven, or the repair is over, they read what it
/// left.
#[test]
fn a_repository_being_written_or_repaired_fences_its_cob_reads() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &SEED, "fenced");
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WRITE", "2000"),
            ("FREEDOM_RADICLED_TEST_HOLD_REPAIR", "1000"),
        ],
    );
    let r = rid.to_string();
    let issues = json!({ "rid": r });
    let tree = json!({ "rid": r, "path": "" });

    // A write held past its start, then proven.
    let write = radicled.request(
        "rad.write",
        json!({
            "op": "create_issue",
            "args": { "rid": r, "title": "Written", "description": "Its body.", "labels": [] },
        }),
    );
    assert!(radicled.logs(STARTED, Duration::from_secs(10)));
    let reply = radicled.read("issues", issues.clone()).unwrap_err();
    assert_eq!(code(&reply), "stopped", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        "a write to the repository is under way, and its outcome isn't proven yet"
    );
    assert!(radicled.read("patches", issues.clone()).is_err());
    assert!(radicled.read("tree", tree.clone()).is_ok());
    assert!(radicled.read("repo_info", issues.clone()).is_ok());
    assert!(radicled.reply(write)["result"]["id"].is_string());
    let listed = read_text(&mut radicled, "issues", &issues);
    assert!(listed.contains("Written"), "{listed}");

    // A write whose outcome is unknown: fenced while it runs, then while
    // its repository is repaired.
    let write = radicled.request(
        "rad.write",
        json!({
            "op": "comment_issue",
            "args": { "rid": r, "issue_id": "abcdef0123", "body": "Nowhere." },
        }),
    );
    assert!(radicled.logs_times(STARTED, 2, Duration::from_secs(10)));
    assert_eq!(
        code(&radicled.read("issues", issues.clone()).unwrap_err()),
        "stopped"
    );
    assert_eq!(code(&radicled.reply(write)), "outcome_unknown");
    assert!(radicled.logs(QUEUED, Duration::from_secs(10)));
    let reply = radicled.read("issues", issues.clone()).unwrap_err();
    assert_eq!(code(&reply), "stopped", "{reply}");
    assert!(radicled.read("tree", tree.clone()).is_ok());
    assert!(radicled.logs(DONE, Duration::from_secs(60)));
    let listed = read_text(&mut radicled, "issues", &issues);
    assert!(listed.contains("Written"), "{listed}");
    shut_down(&mut radicled, &dirs.home);
}

/// 0008, "Methods" ("Cancel"): main's cancel of a read whose body waits
/// for credit stops its stream at once: its abort, `cancelled`, and
/// nothing more of it; and its thread is free again.
#[test]
fn a_cancelled_body_stops_at_once() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, commits) = fixture::repository_with(
        &dirs.home,
        &SEED,
        "cancelled",
        &[&[("half.txt", &vec![b'a'; 1 << 20])]],
    );
    let mut radicled = served(&dirs, &[]);
    let args = blob_at(rid, &commits[0], "half.txt");
    let empty = Blob {
        binary: false,
        content: Vec::new(),
    };
    let whole = (1 << 20) + text(|w| json::blob(w, "half.txt", &empty)).len();
    // Four bodies held without credit hold every read thread.
    let held: Vec<u64> = (0..4)
        .map(|_| radicled.request("rad.read", json!({ "op": "blob_at", "args": args })))
        .collect();
    for id in &held {
        assert!(radicled.reply(*id)["result"].is_object());
        radicled.uncredited(*id, 128 << 10);
    }
    let queued = radicled.request("rad.read", json!({ "op": "status" }));
    assert!(!radicled.any_within(queued, Duration::from_millis(500)));
    radicled.cancel(held[0]);
    let abort = radicled.stream(held[0]);
    assert_eq!(abort["stream"], "abort", "{abort}");
    assert_eq!(abort["code"], "cancelled", "{abort}");
    assert_eq!(
        radicled.read_reply(queued).unwrap(),
        br#"{"connectedPeers":0}"#
    );
    assert!(!radicled.any_within(held[0], Duration::from_millis(500)));
    // The others go on to their end once credited.
    for id in &held[1..] {
        radicled.credit(*id, 128 << 10);
        let (bytes, end) = radicled.body(*id);
        assert_eq!(end["stream"], "end", "{end}");
        assert_eq!(bytes.len(), whole, "{end}");
    }
    shut_down(&mut radicled, &dirs.home);
}
