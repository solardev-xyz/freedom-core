//! `rad.blob` through the real binary (design 0008, "The blob API",
//! "Ranges", "Pools and budgets", "Deadlines", "Errors" and "Tests first"):
//! a blob's raw bytes, or a range of them, under a head `{ oid, size,
//! binary, range }`, as `vectors/radicle-blob.json` gives them; libradicle's
//! errors with its messages, as main's `/blob/` route answers them today;
//! the 64 MiB cap from the header, `HEAD` included; twice a blob's size
//! reserved while it loads, and a wait for it that ends at main's cancel
//! and at the deadline; the walk charged what libgit2 holds of its trees;
//! a path past 4096 components refused before any walk, and one at it
//! served within the walk's reservation; a `namespace` quarantine refused.
//! No reply names the home or any absolute path: a repository the node
//! doesn't have is `repository not found`.
//!
//! The vectors' files are committed object by object, so a symlink and a
//! submodule are the same on every OS; libradicle reads them on the same
//! home before the service starts. `FREEDOM_RADICLED_TEST_BUDGET` shrinks
//! the output budget, and logs each reservation that waits for it;
//! `FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS` the read pool's deadline, with
//! `…_FROM` for the requests admitted once a file exists
//! (src/testhooks.rs). Every node here reaches no one, as in
//! tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::fixture;
use common::*;
use libradicle::BINDING_READ_BUDGET;
use radicle::git::raw as git2;
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::quarantine::Kind;
use serde_json::{Value, json};

const VECTORS: &str = include_str!("../../../vectors/radicle-blob.json");

/// 64 MiB: the largest blob `rad.blob` serves; twice it while it loads,
/// and libgit2's NUL and structs.
const BLOB: u64 = 64 << 20;
const BLOB_LOADING: u64 = libradicle::raw_held(BLOB) + BLOB;
/// What a blob's walk reserves, and the loads it walks within: what
/// libradicle charges the commit and the trees on the way, all together.
const WALK: u64 = 32 << 20;
/// libradicle's, and git's default `core.maxTreeDepth`: the most
/// components a path has.
const DEPTH: usize = libradicle::MAX_TREE_DEPTH;
/// A repository the node doesn't have, as the service answers it.
const MISSING: &str = "repository not found";
/// A data frame's most.
const CHUNK: u64 = 64 << 10;

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

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// A vector's bytes: `hex`, or `fill` repeated `n` times.
fn bytes_of(value: &Value, n: &str) -> Vec<u8> {
    match value["hex"].as_str() {
        Some(hex) => unhex(hex),
        None => {
            let fill = unhex(value["fill"].as_str().unwrap())[0];
            vec![fill; usize::try_from(value[n].as_u64().unwrap()).unwrap()]
        }
    }
}

/// How many bytes a head's body has: none for `HEAD`, which has no
/// `binary`; its range's, or the whole blob's.
fn body_len(head: &Value) -> u64 {
    if head.get("binary").is_none() {
        return 0;
    }
    match &head["range"] {
        Value::Null => head["size"].as_u64().unwrap(),
        range => range["end"].as_u64().unwrap() - range["start"].as_u64().unwrap() + 1,
    }
}

/// Main's HTTP answer on a head (0008, "Ranges"): the vectors' `http`.
fn http_of(head: &Value) -> Value {
    let size = head["size"].as_u64().unwrap();
    match &head["range"] {
        Value::Null => json!({ "status": 200, "headers": { "content-length": size.to_string() } }),
        range => {
            let (start, end) = (
                range["start"].as_u64().unwrap(),
                range["end"].as_u64().unwrap(),
            );
            json!({ "status": 206, "headers": {
                "content-length": (end - start + 1).to_string(),
                "content-range": format!("bytes {start}-{end}/{size}"),
            } })
        }
    }
}

/// `rad.blob`'s answer to request `id`: its head and its body, each data
/// frame at most 64 KiB, under main's credit; or its error reply. A head
/// whose body is empty opens no stream: the caller checks that.
fn answer(radicled: &mut Radicled, id: u64) -> Result<(Value, Vec<u8>), Value> {
    let reply = radicled.reply(id);
    if reply.get("error").is_some() {
        return Err(reply);
    }
    let head = reply["result"].clone();
    let expected = body_len(&head);
    if expected == 0 {
        return Ok((head, Vec::new()));
    }
    loop {
        let frame = radicled.stream(id);
        match frame["stream"].as_str() {
            Some("data") => {
                let len = frame["len"].as_u64().unwrap();
                assert!(len > 0 && len <= CHUNK, "{frame}");
                radicled.credit(id, u32::try_from(len).unwrap());
            }
            _ => {
                assert_eq!(frame["stream"], "end", "{frame}");
                break;
            }
        }
    }
    let body = radicled.taken(id);
    assert_eq!(body.len() as u64, expected, "{head}");
    Ok((head, body))
}

fn blob(radicled: &mut Radicled, params: Value) -> (u64, Result<(Value, Vec<u8>), Value>) {
    let id = radicled.request("rad.blob", params);
    (id, answer(radicled, id))
}

/// The vectors' fixture, imported: its files, a symlink and a submodule.
fn vector_repository(home: &Path, vectors: &Value) -> (RepoId, String) {
    let files: Vec<(String, i32, Vec<u8>)> = vectors["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let mode = i32::from_str_radix(f["mode"].as_str().unwrap(), 8).unwrap();
            let content = match f["commit"].as_str() {
                Some(commit) => commit.as_bytes().to_vec(),
                None => bytes_of(f, "size"),
            };
            (f["path"].as_str().unwrap().to_string(), mode, content)
        })
        .collect();
    let entries: Vec<fixture::Entry<'_>> = files
        .iter()
        .map(|(path, mode, content)| (path.as_str(), *mode, content.as_slice()))
        .collect();
    fixture::repository_of(home, &SEED, "blobs", &entries)
}

/// 0008, "The blob API", "Ranges" and "Errors", and the vectors: each case's
/// head and bytes, byte for byte, in frames of at most 64 KiB; a `HEAD` with
/// no `binary`, and an empty body with no stream; each range normalized or
/// `range_not_satisfiable` with the size; past 64 MiB `too_large`, from the
/// header. libradicle's errors are main's (`not_found` where main answers
/// 404, `failed` where 500, with its message), the add-on's texts at
/// v0.8.0; a repository the node doesn't have, whose libradicle text names
/// its storage path, is `not_found` with `repository not found`; no reply
/// names the home or any absolute path. What doesn't parse is
/// `invalid_argument`. The JSON route (`blob_at`) is unchanged beside it,
/// and each file's `binary`, ID and bytes are libradicle's.
#[test]
fn each_case_answers_the_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, revision) = vector_repository(&dirs.home, &vectors);
    let r = rid.to_string();
    let absent_rid: RepoId = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap();
    let absent_revision = "1".repeat(40);

    // libradicle's own reads of the same home: each file's ID, size,
    // `binary` and bytes are the vectors'; each error's text is the add-on's
    // at v0.8.0; and the errors of a repository or revision it doesn't have.
    let others = fixture::with_node(&dirs.home, &SEED, |node| {
        for f in vectors["files"].as_array().unwrap() {
            let path = f["path"].as_str().unwrap();
            if f["mode"] == "160000" {
                continue;
            }
            let header = node.blob_header(rid, &revision, path).unwrap();
            assert_eq!(header.oid, f["oid"].as_str().unwrap(), "{path}");
            assert_eq!(header.size, f["size"].as_u64().unwrap(), "{path}");
            let read = node.read_blob_at(rid, &revision, path).unwrap();
            assert_eq!(read.binary, f["binary"].as_bool().unwrap(), "{path}");
            assert!(read.content == bytes_of(f, "size"), "{path}");
        }
        for e in vectors["errors"].as_array().unwrap() {
            let path = e["path"].as_str().unwrap();
            let message = node
                .read_blob_at_capped(rid, &revision, path, BINDING_READ_BUDGET)
                .unwrap_err()
                .to_string();
            assert_eq!(message, e["expect"]["error"]["message"].as_str().unwrap());
        }
        [
            (
                absent_rid.to_string(),
                revision.clone(),
                node.read_blob_at(absent_rid, &revision, "README.md")
                    .unwrap_err()
                    .to_string(),
            ),
            (
                r.clone(),
                absent_revision.clone(),
                node.read_blob_at(rid, &absent_revision, "README.md")
                    .unwrap_err()
                    .to_string(),
            ),
        ]
    });

    let mut radicled = served(&dirs, &[]);
    let params = |path: &Value, given: &Value| {
        json!({
            "rid": r, "revision": revision, "path": path,
            "range": given["range"], "head_only": given["head_only"],
        })
    };
    let mut bodiless = Vec::new();
    for c in vectors["cases"].as_array().unwrap() {
        let id = &c["id"];
        let (request, answered) = blob(&mut radicled, params(&c["path"], &c["params"]));
        let expect = &c["expect"];
        match answered {
            Ok((head, body)) => {
                assert_eq!(head, expect["head"], "{id}");
                assert_eq!(http_of(&head), c["http"], "{id}");
                match &expect["body"] {
                    Value::Null => {
                        assert!(body.is_empty(), "{id}");
                        bodiless.push(request);
                    }
                    expected => assert!(body == bytes_of(expected, "len"), "{id}"),
                }
            }
            Err(reply) => {
                assert_pathless(&reply, &dirs.home);
                assert_eq!(code(&reply), expect["error"]["code"], "{id}: {reply}");
                if let Some(message) = expect["error"].get("message") {
                    assert_eq!(&reply["error"]["message"], message, "{id}: {reply}");
                }
                if let Some(data) = expect["error"].get("data") {
                    assert_eq!(&reply["error"]["data"], data, "{id}: {reply}");
                }
            }
        }
    }
    for e in vectors["errors"].as_array().unwrap() {
        let id = &e["id"];
        let (_, answered) = blob(&mut radicled, params(&e["path"], &e["params"]));
        let reply = answered.unwrap_err();
        assert_pathless(&reply, &dirs.home);
        let error = &e["expect"]["error"];
        assert_eq!(code(&reply), error["code"], "{id}: {reply}");
        assert_eq!(reply["error"]["message"], error["message"], "{id}: {reply}");
        // Main's answer today: 404 for `not_found`, 500 for `failed`.
        let status = if error["code"] == "not_found" {
            404
        } else {
            500
        };
        assert_eq!(e["main"]["status"], status, "{id}");
        let main: Value = serde_json::from_str(e["main"]["body"].as_str().unwrap()).unwrap();
        assert_eq!(main["error"], error["message"], "{id}");
    }
    // A repository the node doesn't have: libradicle's text names its
    // storage path under the home, so the reply is the fixed text, still
    // `not_found` (404). A revision it doesn't have: libradicle's text,
    // which names only the revision, as today.
    let [(_, _, absent), (_, _, unknown)] = &others;
    assert!(absolute(absent), "{absent}");
    assert_eq!(todays(absent), "not_found", "{absent}");
    assert!(!absolute(unknown), "{unknown}");
    let expected = [("not_found", MISSING), (todays(unknown), unknown.as_str())];
    for ((rid, revision, _), (code_of, message)) in others.iter().zip(expected) {
        for head_only in [false, true] {
            let (_, answered) = blob(
                &mut radicled,
                json!({ "rid": rid, "revision": revision, "path": "README.md", "head_only": head_only }),
            );
            let reply = answered.unwrap_err();
            assert_pathless(&reply, &dirs.home);
            assert_eq!(code(&reply), code_of, "{reply}");
            assert_eq!(reply["error"]["message"], message, "{reply}");
        }
    }
    for i in vectors["invalid"].as_array().unwrap() {
        let mut given = i["params"].clone();
        let values: Vec<&mut Value> = match &mut given {
            Value::Object(members) => members.values_mut().collect(),
            Value::Array(items) => items.iter_mut().collect(),
            other => panic!("{other}"),
        };
        for value in values {
            match value.as_str() {
                Some("$rid") => *value = json!(r),
                Some("$revision") => *value = json!(revision),
                Some("$REVISION") => *value = json!(revision.to_uppercase()),
                _ => {}
            }
        }
        let (_, answered) = blob(&mut radicled, given);
        let reply = answered.unwrap_err();
        assert_pathless(&reply, &dirs.home);
        assert_eq!(code(&reply), "invalid_argument", "{}: {reply}", i["id"]);
    }
    // The JSON route beside it, unchanged: main's `/blob/` answer today; and
    // a text file's raw bytes are its content there.
    for f in vectors["files"].as_array().unwrap() {
        let Some(main) = f.get("main") else {
            continue;
        };
        let path = f["path"].as_str().unwrap();
        let json = radicled
            .read(
                "blob_at",
                json!({ "rid": r, "revision": revision, "path": path }),
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(json).unwrap(),
            main["body"].as_str().unwrap(),
            "{path}"
        );
        let content = bytes_of(f, "size");
        if !f["binary"].as_bool().unwrap()
            && let Ok(text) = std::str::from_utf8(&content)
        {
            let main: Value = serde_json::from_str(main["body"].as_str().unwrap()).unwrap();
            assert_eq!(main["content"], text, "{path}");
        }
    }
    // No stream for a head without a body, however long after: nothing of
    // it is left open, so main's cancel of it queues nothing.
    for &id in &bodiless {
        radicled.cancel(id);
    }
    assert!(!radicled.any_within(u64::MAX, Duration::from_millis(500)));
    for &id in &bodiless {
        assert!(!radicled.any_within(id, Duration::ZERO), "{id}");
    }
    let log = shut_down(&mut radicled, &dirs.home);
    // Not even the stop's: a stream it would end.
    for id in bodiless {
        assert!(!radicled.any_within(id, Duration::ZERO), "{id}");
    }
    // Neither content nor libradicle's messages are logged.
    assert!(!log.contains("Blob fixture"), "{log}");
    assert!(!log.contains("missing.txt"), "{log}");
}

/// The sizes of `oids` in `rid`'s storage in `home`, from their headers.
fn sizes(home: &Path, rid: RepoId, oids: &[git2::Oid]) -> Vec<u64> {
    let repo = git2::Repository::open_bare(fixture::storage_of(home, rid)).unwrap();
    let odb = repo.odb().unwrap();
    oids.iter()
        .map(|&oid| odb.read_header(oid).unwrap().0 as u64)
        .collect()
}

/// 0008, "Pools and budgets" (review of #277, round 2): the walk to a blob
/// is charged what libgit2 holds of the commit and each tree once parsed,
/// from their headers (`libradicle::commit_held`, `libradicle::tree_held`),
/// all of them within [`WALK`]. A tree `wide` of 280,000 entries of 36
/// bytes is 10,080,000 bytes, and the walk's objects less than `WALK` by
/// their sizes; parsed, their charges are over it: `wide/f0000001` is
/// `too_large`, `GET` and `HEAD`, with the charge libradicle asked for
/// and `WALK`. `blob_at` is refused the same way at the add-on's 16 MiB of
/// loads. The rest of the repository reads.
#[test]
fn the_walk_is_charged_what_libgit2_holds_of_its_trees() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let entries = 280_000;
    let (rid, revision) = fixture::repository_with_wide_tree(&dirs.home, &SEED, "wide", entries);
    let charged = {
        let repo = git2::Repository::open_bare(fixture::storage_of(&dirs.home, rid)).unwrap();
        let commit = git2::Oid::from_str(&revision).unwrap();
        let root = repo.find_commit(commit).unwrap().tree_id();
        let wide = repo.find_tree(root).unwrap().get_name("wide").unwrap().id();
        let sizes = sizes(&dirs.home, rid, &[commit, root, wide]);
        assert_eq!(sizes[2], 36 * entries as u64);
        assert!(sizes.iter().sum::<u64>() < WALK, "{sizes:?}");
        libradicle::commit_held(sizes[0])
            + libradicle::tree_held(sizes[1])
            + libradicle::tree_held(sizes[2])
    };
    assert!(charged > WALK, "{charged}");
    let mut radicled = served(&dirs, &[]);
    for head_only in [false, true] {
        let (_, answered) = blob(
            &mut radicled,
            at(rid, &revision, "wide/f0000001", head_only),
        );
        let reply = answered.unwrap_err();
        assert_eq!(code(&reply), "too_large", "{reply}");
        assert_eq!(
            reply["error"]["message"],
            format!("{charged} bytes is over the limit of {WALK}"),
            "{reply}"
        );
    }
    let reply = radicled
        .read(
            "blob_at",
            json!({ "rid": rid.to_string(), "revision": revision, "path": "wide/f0000001" }),
        )
        .unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!("{charged} bytes is over the limit of {BINDING_READ_BUDGET}"),
        "{reply}"
    );
    let (_, answered) = blob(&mut radicled, at(rid, &revision, "README.md", false));
    assert_eq!(answered.unwrap().1, b"# Wide\n");
    shut_down(&mut radicled, &dirs.home);
}

/// `d/` `depth` times, then `last`.
fn nested(depth: usize, last: &str) -> String {
    format!("{}{last}", "d/".repeat(depth))
}

/// 0008, "Pools and budgets" (review of #277, round 2): a path names one
/// tree to load for each component, so one of more than 4096 components
/// (libradicle's `MAX_TREE_DEPTH`) is `invalid_argument` before anything
/// opens the repository, in `rad.blob` and in `rad.read`'s `tree`,
/// `tree_at`, `blob` and `blob_at`: for a repository the node doesn't have
/// too, which a walk would have answered `repository not found`. A path at
/// the limit, through 4,095 nested trees, is served within the walk's
/// reservation: with the output budget at exactly [`WALK`], which the
/// walk's charge is under, `rad.blob`'s `GET` and `HEAD`; and `rad.read`'s
/// `blob_at` and its deepest `tree_at`, at 4,096 components each.
#[test]
fn a_path_past_the_depth_limit_is_refused_before_any_walk() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &SEED, "deep");
    let revision = fixture::deep_commit(&dirs.home, rid, DEPTH, b"deep\n");
    // The walk to the file at 4,096 components: the commit, the root and
    // 4,095 trees under it, each charged what libgit2 holds of it.
    let charged = {
        let repo = git2::Repository::open_bare(fixture::storage_of(&dirs.home, rid)).unwrap();
        let commit = repo
            .find_commit(git2::Oid::from_str(&revision).unwrap())
            .unwrap();
        let mut trees = vec![commit.tree_id()];
        for _ in 1..DEPTH {
            let above = repo.find_tree(*trees.last().unwrap()).unwrap();
            trees.push(above.get_name("d").unwrap().id());
        }
        let commit = sizes(&dirs.home, rid, &[commit.id()])[0];
        libradicle::commit_held(commit)
            + sizes(&dirs.home, rid, &trees)
                .into_iter()
                .map(libradicle::tree_held)
                .sum::<u64>()
    };
    assert!(charged < WALK, "{charged}");

    let budget = WALK.to_string();
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_BUDGET", &budget)]);
    let file = nested(DEPTH - 1, "f");
    let past = nested(DEPTH, "f");
    assert_eq!(file.split('/').count(), DEPTH);
    let (_, answered) = blob(&mut radicled, at(rid, &revision, &file, false));
    let (head, body) = answered.unwrap();
    assert_eq!(
        (head["size"].as_u64(), body.as_slice()),
        (Some(5), &b"deep\n"[..])
    );
    let (_, answered) = blob(&mut radicled, at(rid, &revision, &file, true));
    assert_eq!(answered.unwrap().0["size"], 5);
    shut_down(&mut radicled, &dirs.home);

    // `rad.read` at the limit, with its own reservations, and every op one
    // past it.
    let mut radicled = served(&dirs, &[]);
    let named = rid.to_string();
    let blob_at = radicled
        .read(
            "blob_at",
            json!({ "rid": named, "revision": revision, "path": file }),
        )
        .unwrap();
    assert!(String::from_utf8(blob_at).unwrap().contains("deep"));
    let deepest = nested(DEPTH - 1, "d");
    let tree_at = radicled
        .read(
            "tree_at",
            json!({ "rid": named, "revision": revision, "path": deepest }),
        )
        .unwrap();
    assert!(
        String::from_utf8(tree_at)
            .unwrap()
            .contains(r#""name":"f""#)
    );

    // One more component: refused, in the repository and in one the node
    // doesn't have alike.
    let message = format!("path has more than {DEPTH} components");
    let absent = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
    for rid in [named.as_str(), absent] {
        let (_, answered) = blob(
            &mut radicled,
            json!({ "rid": rid, "revision": revision, "path": past }),
        );
        let reply = answered.unwrap_err();
        assert_eq!(code(&reply), "invalid_argument", "{reply}");
        assert_eq!(reply["error"]["message"], message.as_str(), "{reply}");
        for (op, args) in [
            ("tree", json!({ "rid": rid, "path": nested(DEPTH, "d") })),
            (
                "tree_at",
                json!({ "rid": rid, "revision": revision, "path": nested(DEPTH, "d") }),
            ),
            ("blob", json!({ "rid": rid, "path": past })),
            (
                "blob_at",
                json!({ "rid": rid, "revision": revision, "path": past }),
            ),
        ] {
            let reply = radicled.read(op, args).unwrap_err();
            assert_eq!(code(&reply), "invalid_argument", "{op}: {reply}");
            assert_eq!(reply["error"]["message"], message.as_str(), "{op}: {reply}");
        }
    }
    shut_down(&mut radicled, &dirs.home);
}

/// The bounds' repository: a blob of exactly 64 MiB, and a small one.
fn bounds_repository(home: &Path) -> (RepoId, String) {
    let cap = vec![b'b'; BLOB as usize];
    fixture::repository_of(
        home,
        &SEED,
        "bounds",
        &[
            ("cap.bin", 0o100644, cap.as_slice()),
            ("small.txt", 0o100644, b"small\n".as_slice()),
        ],
    )
}

fn at(rid: RepoId, revision: &str, path: &str, head_only: bool) -> Value {
    json!({ "rid": rid.to_string(), "revision": revision, "path": path, "head_only": head_only })
}

/// 0008, "Pools and budgets": a blob reserves twice its size and libgit2's
/// 257 bytes while it loads, and a walk's 32 MiB before it, from the
/// header; `HEAD` only the walk. With a budget of exactly that the 64 MiB
/// blob is served; with one byte less it is `too_large` at once, as a
/// reservation past the whole budget is; a read whose walk the budget
/// can't hold is too.
#[test]
fn a_blob_reserves_twice_its_size_while_it_loads() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, revision) = bounds_repository(&dirs.home);

    let budget = BLOB_LOADING.to_string();
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_BUDGET", &budget)]);
    let (_, answered) = blob(&mut radicled, at(rid, &revision, "cap.bin", false));
    let (head, body) = answered.unwrap();
    assert_eq!(head["size"], BLOB, "{head}");
    assert!(body.len() as u64 == BLOB && body.iter().all(|&b| b == b'b'));
    shut_down(&mut radicled, &dirs.home);

    let budget = (BLOB_LOADING - 1).to_string();
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_BUDGET", &budget)]);
    let (_, answered) = blob(&mut radicled, at(rid, &revision, "cap.bin", false));
    let reply = answered.unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!(
            "{BLOB_LOADING} bytes is over the limit of {}",
            BLOB_LOADING - 1
        )
    );
    // `HEAD` loads nothing; a small blob reserves the walk's.
    let (_, answered) = blob(&mut radicled, at(rid, &revision, "cap.bin", true));
    assert_eq!(answered.unwrap().0["size"], BLOB);
    let (_, answered) = blob(&mut radicled, at(rid, &revision, "small.txt", false));
    assert_eq!(answered.unwrap().1, b"small\n");
    shut_down(&mut radicled, &dirs.home);

    let budget = (WALK - 1).to_string();
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_BUDGET", &budget)]);
    for head_only in [true, false] {
        let (_, answered) = blob(&mut radicled, at(rid, &revision, "small.txt", head_only));
        let reply = answered.unwrap_err();
        assert_eq!(code(&reply), "too_large", "{reply}");
        assert_eq!(
            reply["error"]["message"],
            format!("{WALK} bytes is over the limit of {}", WALK - 1)
        );
    }
    shut_down(&mut radicled, &dirs.home);
}

const WAITS: &str = "test hook: a reservation waits for the budget";

/// 0008, "Pools and budgets" and "Deadlines": a blob that can't reserve
/// its load waits, holding nothing, and ends at main's cancel and at its
/// deadline; reads that fit go on meanwhile. A body main doesn't credit
/// holds its range until main's cancel ends it, which releases it.
///
/// With a 129 MiB budget: a 64 MiB body, never credited past its window,
/// holds nearly 64 MiB; a second load of 128 MiB then waits.
#[test]
fn a_blob_waiting_for_the_budget_ends_at_its_cancel_and_its_deadline() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, revision) = bounds_repository(&dirs.home);
    let deadline = Duration::from_secs(8);
    let budget = (BLOB_LOADING + (1 << 20)).to_string();
    // The 8 s deadline is the second waiting load's under test alone: it
    // applies to the requests admitted while `from` exists, which the test
    // makes just before that load and removes once it waits. The held
    // body's, however long it took to load, and the others' keep their
    // 60 s, so that a slow runner can't let theirs pass before their cancel
    // or their answer.
    let from = dirs.own_home.join("deadline-from");
    let from_arg = from.display().to_string();
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_BUDGET", &budget),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "8000"),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_FROM", &from_arg),
        ],
    );
    let held = radicled.request("rad.blob", at(rid, &revision, "cap.bin", false));
    let head = radicled.reply(held);
    assert_eq!(head["result"]["size"], BLOB, "{head}");
    // Its window's worth, and no credit.
    radicled.uncredited(held, 128 << 10);
    let fits = |radicled: &mut Radicled| {
        let small = blob(radicled, at(rid, &revision, "small.txt", false)).1;
        assert_eq!(small.unwrap().1, b"small\n");
        let header = blob(radicled, at(rid, &revision, "cap.bin", true)).1;
        assert_eq!(header.unwrap().0["size"], BLOB);
    };

    // Main's cancel ends a wait.
    let waiting = radicled.request("rad.blob", at(rid, &revision, "cap.bin", false));
    assert!(radicled.logs_times(WAITS, 1, READ_TIMEOUT));
    assert!(!radicled.any_within(waiting, Duration::from_millis(1500)));
    fits(&mut radicled);
    assert!(!radicled.any_within(waiting, Duration::ZERO));
    radicled.cancel(waiting);
    assert_eq!(code(&radicled.reply(waiting)), "cancelled");

    // So does its deadline, 8 s from its admission, which comes after the
    // request is sent: the reply is never sooner than 8 s from the send.
    std::fs::write(&from, b"").unwrap();
    let sent = Instant::now();
    let waiting = radicled.request("rad.blob", at(rid, &revision, "cap.bin", false));
    assert!(radicled.logs_times(WAITS, 2, READ_TIMEOUT));
    std::fs::remove_file(&from).unwrap();
    assert!(!radicled.any_within(waiting, Duration::from_millis(1500)));
    fits(&mut radicled);
    assert_eq!(code(&radicled.reply(waiting)), "deadline");
    assert!(sent.elapsed() >= deadline);
    // The test's 8 s, not the default 60 s: it was admitted while `from`
    // existed. A generous bound: 52 s over the deadline.
    assert!(sent.elapsed() < Duration::from_secs(60));
    // Nothing more of it.
    assert!(!radicled.any_within(waiting, Duration::from_millis(500)));

    // Main's cancel ends the held body, and releases what it held: the
    // 64 MiB blob loads again.
    assert!(!radicled.any_within(held, Duration::ZERO));
    radicled.cancel(held);
    let end = radicled.stream(held);
    assert_eq!(end["stream"], "abort", "{end}");
    assert_eq!(end["code"], "cancelled", "{end}");
    let (_, answered) = blob(&mut radicled, at(rid, &revision, "cap.bin", false));
    assert_eq!(answered.unwrap().1.len() as u64, BLOB);
    assert!(!radicled.any_within(held, Duration::from_millis(200)));
    shut_down(&mut radicled, &dirs.home);
}

/// 0008, "Methods" ("The repair fence") and "Errors" (`quarantined`):
/// `rad.blob` isn't a COB op, so a repository quarantined for its cache is
/// served, and one quarantined for a namespace is refused, `HEAD` too, with
/// the record's kind.
#[test]
fn a_namespace_quarantine_refuses_a_blob() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let files: &[fixture::Entry<'_>] = &[("README.md", 0o100644, b"# Q\n".as_slice())];
    let (cache, cache_revision) = fixture::repository_of(&dirs.home, &SEED, "cache", files);
    let (namespace, namespace_revision) =
        fixture::repository_of(&dirs.home, &SEED, "namespace", files);
    fixture::quarantine(&dirs.home, cache, Kind::Cache);
    fixture::quarantine(&dirs.home, namespace, Kind::Namespace);
    let mut radicled = served(&dirs, &[]);
    for head_only in [false, true] {
        let (_, answered) = blob(
            &mut radicled,
            at(cache, &cache_revision, "README.md", head_only),
        );
        assert_eq!(answered.unwrap().0["size"], 4);
        let (_, answered) = blob(
            &mut radicled,
            at(namespace, &namespace_revision, "README.md", head_only),
        );
        let reply = answered.unwrap_err();
        assert_eq!(code(&reply), "quarantined", "{reply}");
        assert_eq!(reply["error"]["data"]["kind"], "namespace", "{reply}");
    }
    shut_down(&mut radicled, &dirs.home);
}
