//! `rad.read`'s composed ops, and the ops whose answer main parses and
//! writes again, through the real binary (design 0008, "Methods", "JSON
//! results", "Pools and budgets", "Deadlines" and "Tests first"): each
//! answers the bytes main writes today for what it composes of the
//! add-on's results; past a bound it is `too_large` where the add-on is;
//! one waiting for the output budget ends at its cancel and its deadline;
//! and a quarantined, repairing or written repository is refused as 0008
//! says.
//!
//! What main writes is the model's (tests/common/js.rs: main's
//! compositions over JavaScript's values), applied to the add-on's texts:
//! libradicle's serializers over its bounded reads, as the add-on calls
//! them, on the same home before the service starts. The model is pinned
//! to `vectors/radicle-reads.json`, recorded from main's own code at the
//! reference, here; the service's own composition is pinned to it by its
//! unit tests (src/reads/composed/tests.rs). Every node here reaches no
//! one, as in tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::fixture;
use common::js;
use common::*;
use libradicle::{BINDING_READ_BUDGET, Blob, Bounds, json};
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::quarantine::Kind;
use serde_json::{Value, json};

/// A third identity, who makes the repositories the quarantine test reads.
const CREATOR: [u8; 32] = [9; 32];

/// 32 MiB: the most JSON a read writes.
const JSON_CAP: usize = 32 << 20;

/// 16 MiB: a walk's bounds and a blob's, the add-on's.
const TODAYS: usize = 16 << 20;

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

fn read_text(radicled: &mut Radicled, op: &str, args: &Value) -> String {
    match radicled.read(op, args.clone()) {
        Ok(bytes) => String::from_utf8(bytes).unwrap(),
        Err(reply) => panic!("{op} {args}: {reply}"),
    }
}

/// What the case's scripted add-on answers: its text, or its error's
/// message.
fn answer(case: &Value, export: &str, args: Value) -> Result<String, String> {
    let entry = case["addon"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["export"] == export && e["args"] == args)
        .unwrap_or_else(|| panic!("{}: no {export}({args})", case["id"]));
    let text = entry["text"].as_str().unwrap().to_string();
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(o))
            if o.get("error")
                .is_some_and(|e| e.as_str().is_some_and(|e| !e.is_empty())) =>
        {
            Err(o["error"].as_str().unwrap().to_string())
        }
        _ => Ok(text),
    }
}

/// The model's answer to a vector's case: its body, or its error's message.
/// `None` for a text the model can't read (a lone surrogate's escape).
fn modelled(case: &Value) -> Option<Result<String, String>> {
    let args = &case["args"];
    let rid = &args["rid"];
    let meta = |rid: &Value| -> Option<Result<String, String>> {
        let info = match answer(case, "repoInfo", json!([rid])) {
            Ok(info) => info,
            Err(e) => return Some(Err(e)),
        };
        let seeders = answer(case, "seeders", json!([rid])).ok();
        js::parse(&info)?;
        Some(Ok(js::repo_meta(&info, seeders.as_deref())))
    };
    let again = |text: Result<String, String>| match text {
        Err(e) => Some(Err(e)),
        Ok(text) => js::again(&text).map(Ok),
    };
    Some(match case["op"].as_str().unwrap() {
        "readme_at" => {
            let revision = &args["revision"];
            match answer(case, "treeAt", json!([rid, revision, ""])) {
                Err(e) => Err(e),
                Ok(tree) => match js::find_readme(&tree) {
                    None => Err("no readme".into()),
                    Some(path) => answer(case, "blobAt", json!([rid, revision, path]))
                        .map(|blob| js::splice(&blob, path)),
                },
            }
        }
        "repo_meta" => meta(rid)?,
        "repos_meta" => match answer(case, "listRepos", json!([])) {
            Err(e) => Err(e),
            Ok(list) => {
                let list: Value = serde_json::from_str(&list).unwrap();
                let mut metas = Vec::new();
                let mut failed = None;
                for repo in list.as_array().unwrap() {
                    match meta(&repo["rid"])? {
                        Ok(m) => metas.push(m),
                        Err(e) => {
                            failed = Some(e);
                            break;
                        }
                    }
                }
                match failed {
                    Some(e) => Err(e),
                    None => Ok(format!("[{}]", metas.join(","))),
                }
            }
        },
        op @ ("issues_page" | "patches_page") => {
            let export = if op == "issues_page" {
                "issues"
            } else {
                "patches"
            };
            match answer(case, export, json!([rid])) {
                Err(e) => Err(e),
                Ok(items) => {
                    js::parse(&items)?;
                    Ok(js::paginate(
                        &items,
                        args["status"].as_str(),
                        args["page"].as_str(),
                        args["per_page"].as_str(),
                    ))
                }
            }
        }
        "issue" => again(answer(case, "issue", json!([rid, args["issue_id"]])))?,
        "patch" => again(answer(case, "patch", json!([rid, args["patch_id"]])))?,
        "remotes" => again(answer(case, "remotes", json!([rid])))?,
        "repo_stats" => again(answer(case, "repoStats", json!([rid, args["revision"]])))?,
        _ => return None,
    })
}

/// The model writes what main's code at the reference writes, for every
/// case it can read: this file's expectations are main's.
#[test]
fn the_model_is_mains() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../vectors/radicle-reads.json")).unwrap();
    let (mut checked, mut unread) = (0, Vec::new());
    for case in vectors["cases"].as_array().unwrap() {
        if case["op"] == "node_info" {
            continue;
        }
        let Some(answer) = modelled(case) else {
            unread.push(case["id"].as_str().unwrap().to_string());
            continue;
        };
        let main = &case["main"];
        match answer {
            Ok(body) => assert_eq!(main["body"].as_str().unwrap(), body, "{}", case["id"]),
            Err(message) => {
                assert_ne!(main["status"], 200, "{}", case["id"]);
                let body: Value = serde_json::from_str(main["body"].as_str().unwrap()).unwrap();
                assert_eq!(body["error"], message.as_str(), "{}", case["id"]);
            }
        }
        checked += 1;
    }
    // Only the escapes of lone surrogates are past serde_json.
    assert_eq!(unread, ["remotes-escapes", "remotes-escaped-keys"]);
    assert_eq!(checked, 148);
}

/// The repositories of the parity test: `composed`, its README.md and
/// issues; `plain`, with README.txt among its candidates; `bare`, with
/// none at its root, where a directory has a candidate's name.
const COMPOSED_FIRST: &[(&str, &[u8])] = &[
    ("README.md", b"# Composed\n"),
    ("src/lib.rs", b"pub fn composed() {}\n"),
];
const COMPOSED_SECOND: &[(&str, &[u8])] = &[
    (
        "README.md",
        b"# Composed\n\n\"quoted\" \\ caf\xc3\xa9 \t }\n",
    ),
    ("notes.txt", b"Notes.\n"),
];
const PLAIN: &[(&str, &[u8])] = &[
    ("Readme", b"Not this.\n"),
    ("README.txt", b"Plain.\n"),
    ("readme.md", b"Nor this.\n"),
];
const BARE: &[(&str, &[u8])] = &[
    ("README.md/inner.txt", b"A directory named as a README.\n"),
    ("docs/README", b"Nested.\n"),
    ("readme.txt", b"No.\n"),
];

/// 0008, "Methods", "JSON results" and "Parity": each composed op, and
/// each of main's serialization, answers a head and the bytes main writes
/// today for the add-on's results on the same home; and fails as main's
/// reads fail: libradicle's message, `not_found` by today's test,
/// otherwise `failed`; `readme_at` with no README `not_found`, "no
/// readme"; args that don't parse `invalid_argument`.
#[test]
fn each_composed_op_answers_mains_bytes() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (composed, commits) = fixture::repository_with(
        &dirs.home,
        &SEED,
        "composed",
        &[COMPOSED_FIRST, COMPOSED_SECOND],
    );
    let (plain, plain_commits) = fixture::repository_with(&dirs.home, &SEED, "plain", &[PLAIN]);
    let (bare, bare_commits) = fixture::repository_with(&dirs.home, &SEED, "bare", &[BARE]);
    let (c, second) = (composed.to_string(), commits[1].clone());
    let absent = "0".repeat(40);
    let missing: RepoId = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap();

    // Issues of every state, a label, a comment and a reply, escapes.
    let issues = fixture::with_node(&dirs.home, &SEED, |node| {
        let quoted = node
            .create_issue(
                composed,
                "Quotes \" \\ caf\u{e9} \u{1f600} \u{1}",
                "Its body.\n\u{2028}",
                vec!["bug".into(), "good-first-issue".into()],
            )
            .unwrap();
        let solved = node
            .create_issue(composed, "Solved", "Done.", vec![])
            .unwrap();
        node.edit_issue_state(composed, &solved, "solved").unwrap();
        let other = node
            .create_issue(composed, "Other", "Not done.", vec![])
            .unwrap();
        node.edit_issue_state(composed, &other, "closed").unwrap();
        let comment = node
            .comment_issue(composed, &quoted, "A comment.", None)
            .unwrap();
        node.comment_issue(composed, &quoted, "A reply.", Some(&comment))
            .unwrap();
        let all: Vec<String> = node
            .issues(composed)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id.to_string())
            .collect();
        assert_eq!(all.len(), 4);
        all
    });

    // The add-on's texts on the same home, then main's composition of them.
    let (expected, errors) = fixture::with_node(&dirs.home, &SEED, |node| {
        let b = Bounds::for_binding;
        let readme =
            |node: &libradicle::Embedded, rid: RepoId, revision: &str| -> Result<String, String> {
                let (entries, commit) = node
                    .tree_at_bounded(rid, revision, "", &b())
                    .map_err(|e| e.to_string())?;
                let tree = text(|w| json::tree_at(w, &entries, &commit));
                let path = js::find_readme(&tree).ok_or("no readme")?;
                let blob = node
                    .read_blob_at_capped(rid, revision, path, BINDING_READ_BUDGET)
                    .unwrap();
                Ok(js::splice(&text(|w| json::blob(w, path, &blob)), path))
            };
        let meta = |node: &mut libradicle::Embedded, rid: RepoId| -> Result<String, String> {
            let info = node
                .repo_info_bounded(rid, &b())
                .map_err(|e| e.to_string())?;
            let info = text(|w| json::repo_info(w, &info));
            let seeders = node
                .seeders(rid)
                .ok()
                .map(|n| text(|w| json::seeding(w, n)));
            Ok(js::repo_meta(&info, seeders.as_deref()))
        };
        let issues_text = text(|w| json::issues(w, &node.issues_bounded(composed, &b()).unwrap()));
        let patches_text =
            text(|w| json::patches(w, &node.patches_bounded(composed, &b()).unwrap()));
        let mut expected: Vec<(&str, Value, String)> = vec![
            (
                "readme_at",
                json!({ "rid": c, "revision": second }),
                readme(node, composed, &second).unwrap(),
            ),
            (
                "readme_at",
                json!({ "rid": c, "revision": commits[0] }),
                readme(node, composed, &commits[0]).unwrap(),
            ),
            (
                "readme_at",
                json!({ "rid": plain.to_string(), "revision": plain_commits[0] }),
                readme(node, plain, &plain_commits[0]).unwrap(),
            ),
            (
                "remotes",
                json!({ "rid": c }),
                js::again(&text(|w| {
                    json::remotes(w, &node.remotes_bounded(composed, &b()).unwrap())
                }))
                .unwrap(),
            ),
            (
                "repo_stats",
                json!({ "rid": c, "revision": second }),
                js::again(&text(|w| {
                    json::repo_stats(
                        w,
                        &node.repo_stats_bounded(composed, &second, &b()).unwrap(),
                    )
                }))
                .unwrap(),
            ),
            (
                "patches_page",
                json!({ "rid": c, "status": null, "page": null, "per_page": null }),
                js::paginate(&patches_text, None, None, None),
            ),
        ];
        for rid in [composed, plain, bare] {
            expected.push((
                "repo_meta",
                json!({ "rid": rid.to_string() }),
                meta(node, rid).unwrap(),
            ));
        }
        let listed: Vec<RepoId> = node
            .list_repos_bounded(&b())
            .unwrap()
            .iter()
            .map(|r| r.rid)
            .collect();
        assert_eq!(listed.len(), 3);
        let metas: Vec<String> = listed.iter().map(|rid| meta(node, *rid).unwrap()).collect();
        expected.push(("repos_meta", Value::Null, format!("[{}]", metas.join(","))));
        let mut ids = issues.clone();
        ids.push(issues[0][..7].to_string());
        for id in &ids {
            let (oid, issue) = node.issue_bounded(composed, id, &b()).unwrap();
            expected.push((
                "issue",
                json!({ "rid": c, "issue_id": id }),
                js::again(&text(|w| json::issue(w, &oid, &issue))).unwrap(),
            ));
        }
        for (status, page, per_page) in [
            (None, None, None),
            (Some("open"), None, None),
            (Some("closed"), None, None),
            (Some(""), Some("1"), Some("2")),
            (Some("open"), Some("1"), Some("1")),
            (None, Some("-1"), Some("abc")),
            (None, Some(" 1"), Some("3.9")),
            (Some("closed"), Some("9"), None),
        ] {
            expected.push((
                "issues_page",
                json!({ "rid": c, "status": status, "page": page, "per_page": per_page }),
                js::paginate(&issues_text, status, page, per_page),
            ));
        }
        let peers = node.connected_peers().unwrap();
        expected.push((
            "node_info",
            json!({}),
            format!(r#"{{"connected_peers":{peers},"repos_total":3,"repos_error":null}}"#),
        ));
        let errors: Vec<(&str, Value, String)> = vec![
            (
                "readme_at",
                json!({ "rid": bare.to_string(), "revision": bare_commits[0] }),
                readme(node, bare, &bare_commits[0]).unwrap_err(),
            ),
            (
                "readme_at",
                json!({ "rid": c, "revision": absent }),
                readme(node, composed, &absent).unwrap_err(),
            ),
            (
                "repo_meta",
                json!({ "rid": missing.to_string() }),
                meta(node, missing).unwrap_err(),
            ),
            (
                "issue",
                json!({ "rid": c, "issue_id": absent }),
                node.issue_bounded(composed, &absent, &b())
                    .unwrap_err()
                    .to_string(),
            ),
            (
                "patch",
                json!({ "rid": c, "patch_id": "abcdef" }),
                node.patch_bounded(composed, "abcdef", &b())
                    .unwrap_err()
                    .to_string(),
            ),
            (
                "repo_stats",
                json!({ "rid": c, "revision": absent }),
                node.repo_stats_bounded(composed, &absent, &b())
                    .unwrap_err()
                    .to_string(),
            ),
            (
                "issues_page",
                json!({ "rid": missing.to_string(), "status": null, "page": null, "per_page": null }),
                node.issues_bounded(missing, &b()).unwrap_err().to_string(),
            ),
        ];
        (expected, errors)
    });
    // The fixture reaches what the parity needs.
    let find = |op: &str| {
        expected
            .iter()
            .filter(|(o, _, _)| *o == op)
            .map(|(_, _, t)| t.as_str())
            .collect::<Vec<_>>()
    };
    assert!(
        find("readme_at")[0].contains("caf\u{e9}"),
        "{:?}",
        find("readme_at")
    );
    assert!(find("readme_at")[2].ends_with(r#""path":"README.txt"}"#));
    assert!(
        find("issues_page")
            .iter()
            .any(|p| p.contains(r#""reason":"solved""#))
    );
    assert!(find("issues_page").contains(&"[]"));
    assert!(errors.iter().any(|(_, _, e)| todays(e) == "not_found"));
    assert!(errors.iter().any(|(_, _, e)| todays(e) == "failed"));

    let mut radicled = served(&dirs, &[]);
    for (op, args, bytes) in &expected {
        let id = radicled.request("rad.read", json!({ "op": op, "args": args }));
        let head = radicled.reply(id);
        assert_eq!(
            head["result"],
            json!({ "content_type": "application/json", "bytes": bytes.len() }),
            "{op} {args}: {head}"
        );
        let (body, end) = radicled.body(id);
        assert_eq!(end["stream"], "end", "{end}");
        assert_eq!(String::from_utf8(body).unwrap(), *bytes, "{op} {args}");
    }
    for (op, args, message) in &errors {
        let reply = radicled.read(op, args.clone()).unwrap_err();
        let expected = if message == "no readme" {
            "not_found"
        } else {
            todays(message)
        };
        assert_eq!(code(&reply), expected, "{op} {args}: {reply}");
        assert_eq!(reply["error"]["message"], message.as_str(), "{reply}");
    }
    // What doesn't parse: libradicle's text for a COB ID.
    for (op, args) in [
        ("issue", json!({ "rid": c, "issue_id": "ABCDEF" })),
        ("patch", json!({ "rid": c, "patch_id": "abc" })),
        (
            "readme_at",
            json!({ "rid": c, "revision": second.to_uppercase() }),
        ),
        (
            "issues_page",
            json!({ "rid": c, "status": "open", "page": 1, "per_page": null }),
        ),
        ("node_info", json!({ "rid": c })),
    ] {
        let reply = radicled.read(op, args.clone()).unwrap_err();
        assert_eq!(code(&reply), "invalid_argument", "{op} {args}: {reply}");
    }
    let reply = radicled
        .read("issue", json!({ "rid": c, "issue_id": "ABCDEF" }))
        .unwrap_err();
    assert_eq!(
        reply["error"]["message"],
        r#"invalid collaborative object id "ABCDEF""#
    );
    let log = shut_down(&mut radicled, &dirs.home);
    // Neither content nor libradicle's messages are logged.
    assert!(!log.contains("Quotes"), "{log}");
    assert!(!log.contains(&missing.to_string()), "{log}");
}

/// Blob content whose JSON at `name`, with `"path"` spliced in, is exactly
/// `json` bytes, with `len` bytes of content: `"` escapes to two bytes,
/// `a` stays one.
fn readme_of_json(name: &str, len: usize, json: usize) -> Vec<u8> {
    let empty = Blob {
        binary: false,
        content: Vec::new(),
    };
    let around = js::splice(&text(|w| json::blob(w, name, &empty)), name).len();
    let quotes = json - around - len;
    let mut content = vec![b'a'; len - quotes];
    content.extend(std::iter::repeat_n(b'"', quotes));
    content
}

/// An issue's JSON and cached sizes, with a description of `len` bytes:
/// the cached size the least loads budget that reads it.
fn issue_sizes(node: &libradicle::Embedded, rid: RepoId, len: usize) -> (u64, u64) {
    let id = node
        .create_issue(rid, "Big", &"a".repeat(len), vec![])
        .unwrap();
    let (oid, issue) = node.issue_bounded(rid, &id, &Bounds::unbounded()).unwrap();
    let json_len = text(|w| json::issue(w, &oid, &issue)).len() as u64;
    let reads = |loads: u64| {
        node.issue_bounded(
            rid,
            &id,
            &Bounds::new(libradicle::CancelToken::new(), u64::MAX).with_loads(loads),
        )
        .is_ok()
    };
    let (mut low, mut high) = (0u64, 1 << 20);
    while low < high {
        let mid = (low + high) / 2;
        if reads(mid) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    (json_len, low)
}

/// The longest description of an issue the add-on reads: its JSON, and
/// its cached size, at most 16 MiB each. Each grows by a whole number of
/// bytes per byte of description, measured on two probe issues.
fn description_at_todays(node: &libradicle::Embedded, rid: RepoId) -> usize {
    let (json1, cached1) = issue_sizes(node, rid, 1);
    let (json2, cached2) = issue_sizes(node, rid, 1001);
    let (json_per, cached_per) = ((json2 - json1) / 1000, (cached2 - cached1) / 1000);
    assert_eq!((json2 - json1) % 1000, 0);
    assert_eq!((cached2 - cached1) % 1000, 0);
    let todays = TODAYS as u64;
    let more = ((todays - json1) / json_per).min((todays - cached1) / cached_per);
    usize::try_from(1 + more).unwrap()
}

/// 0008, "Pools and budgets" and "JSON results": a composed read walks
/// within the add-on's bounds, 16 MiB of JSON and of loads, so the issue
/// with the longest description the add-on reads is served, byte for
/// byte, and one a byte longer is `too_large`, with libradicle's message,
/// as the add-on refuses it; a page of them is too.
/// A README whose spliced JSON is exactly 32 MiB is served, in data frames
/// of at most 64 KiB, and one a byte longer is `too_large`, the reply.
#[test]
fn a_composed_read_is_bounded_where_the_add_on_is() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let at = readme_of_json("README.md", TODAYS, JSON_CAP);
    let over = readme_of_json("README.md", TODAYS, JSON_CAP + 1);
    let (at_rid, at_commits) =
        fixture::repository_with(&dirs.home, &SEED, "at", &[&[("README.md", &at)]]);
    let (over_rid, over_commits) =
        fixture::repository_with(&dirs.home, &SEED, "over", &[&[("README.md", &over)]]);
    let (expected, refused, at_id, over_id) = fixture::with_node(&dirs.home, &SEED, |node| {
        let description = description_at_todays(node, at_rid);
        let at_id = node
            .create_issue(at_rid, "Big", &"a".repeat(description), vec![])
            .unwrap();
        let over_id = node
            .create_issue(over_rid, "Big", &"a".repeat(description + 1), vec![])
            .unwrap();
        let (id, issue) = node
            .issue_bounded(at_rid, &at_id, &Bounds::for_binding())
            .unwrap();
        let issue_text = text(|w| json::issue(w, &id, &issue));
        let refused = node
            .issue_bounded(over_rid, &over_id, &Bounds::for_binding())
            .unwrap_err();
        assert!(
            matches!(refused, libradicle::Error::TooLarge { .. }),
            "{refused}"
        );
        let page = node
            .issues_bounded(at_rid, &Bounds::for_binding())
            .unwrap_err();
        assert!(matches!(page, libradicle::Error::TooLarge { .. }), "{page}");
        let blob = node
            .read_blob_at_capped(at_rid, &at_commits[0], "README.md", BINDING_READ_BUDGET)
            .unwrap();
        let readme = js::splice(&text(|w| json::blob(w, "README.md", &blob)), "README.md");
        assert_eq!(readme.len(), JSON_CAP);
        (
            (js::again(&issue_text).unwrap(), readme),
            (refused.to_string(), page.to_string()),
            at_id,
            over_id,
        )
    });

    let mut radicled = served(&dirs, &[]);
    let (at_s, over_s) = (at_rid.to_string(), over_rid.to_string());
    let issue = read_text(
        &mut radicled,
        "issue",
        &json!({ "rid": at_s, "issue_id": at_id }),
    );
    assert!(issue == expected.0, "{} bytes served", issue.len());
    let reply = radicled
        .read("issue", json!({ "rid": over_s, "issue_id": over_id }))
        .unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(reply["error"]["message"], refused.0.as_str());
    let reply = radicled
        .read(
            "issues_page",
            json!({ "rid": at_s, "status": null, "page": null, "per_page": null }),
        )
        .unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(reply["error"]["message"], refused.1.as_str());

    let id = radicled.request(
        "rad.read",
        json!({ "op": "readme_at", "args": { "rid": at_s, "revision": at_commits[0] } }),
    );
    let head = radicled.reply(id);
    assert_eq!(head["result"]["bytes"], JSON_CAP, "{head}");
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
    assert!(radicled.taken(id) == expected.1.as_bytes(), "the README");
    let reply = radicled
        .read(
            "readme_at",
            json!({ "rid": over_s, "revision": over_commits[0] }),
        )
        .unwrap_err();
    assert_eq!(code(&reply), "too_large", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!("{} bytes is over the limit of {JSON_CAP}", JSON_CAP + 1)
    );
    // Everything was released: the same read again.
    assert!(
        radicled
            .read(
                "readme_at",
                json!({ "rid": at_s, "revision": at_commits[0] })
            )
            .is_ok()
    );
    shut_down(&mut radicled, &dirs.home);
}

const WAITS: &str = "test hook: a reservation waits for the budget";

/// 0008, "Pools and budgets" and "Deadlines": a composed read that can't
/// reserve waits, holding what it has, and ends at main's cancel, freeing
/// it for a read behind it, and at its deadline, 8 s from its admission.
///
/// With a 65 MiB budget: a 32 MiB body never credited past its window
/// holds nearly 32 MiB; a README of 8 MiB then reserves its built 32 MiB
/// and waits at its JSON's steps; a `status` behind it waits for its own.
#[test]
fn a_composed_read_waiting_for_the_budget_ends_at_its_cancel_and_its_deadline() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let big = readme_of_json("big.txt", TODAYS, JSON_CAP);
    let readme = vec![b'a'; 8 << 20];
    let (rid, commits) = fixture::repository_with(
        &dirs.home,
        &SEED,
        "waiting",
        &[&[("big.txt", &big), ("README.md", &readme)]],
    );
    let r = rid.to_string();
    // The 8 s deadline is the reads' under test, not the held body's: it
    // applies once `from` exists, which the test makes after the body's
    // head, however long that body took to build.
    let from = dirs.own_home.join("deadline-from");
    let from_arg = from.display().to_string();
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_BUDGET", "68157440"),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "8000"),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_FROM", &from_arg),
        ],
    );
    let held = radicled.request(
        "rad.read",
        json!({ "op": "blob_at", "args": { "rid": r, "revision": commits[0], "path": "big.txt" } }),
    );
    let head = radicled.reply(held);
    assert!(
        head["result"]["bytes"].as_u64().unwrap() > (JSON_CAP as u64) - 64,
        "{head}"
    );
    radicled.uncredited(held, 128 << 10);
    std::fs::write(&from, b"").unwrap();
    let readme_at = json!({ "op": "readme_at", "args": { "rid": r, "revision": commits[0] } });
    let status = |radicled: &mut Radicled| radicled.request("rad.read", json!({ "op": "status" }));

    // Main's cancel ends a wait, and frees what it held. The `status` is
    // sent once the README waits, so it waits behind it.
    let waiting = radicled.request("rad.read", readme_at.clone());
    assert!(radicled.logs_times(WAITS, 1, READ_TIMEOUT));
    let behind = status(&mut radicled);
    assert!(radicled.logs_times(WAITS, 2, READ_TIMEOUT));
    assert!(!radicled.any_within(waiting, Duration::from_millis(1500)));
    assert!(!radicled.any_within(behind, Duration::ZERO));
    radicled.cancel(waiting);
    assert_eq!(code(&radicled.reply(waiting)), "cancelled");
    assert_eq!(
        radicled.read_reply(behind).unwrap(),
        br#"{"connectedPeers":0}"#
    );

    // So does its deadline. Its clock starts before it is sent, so never
    // after its admission. The `status` comes 2 s after it waits, so that
    // its own deadline is 2 s past the README's.
    let admitted = Instant::now();
    let waiting = radicled.request("rad.read", readme_at.clone());
    assert!(radicled.logs_times(WAITS, 3, READ_TIMEOUT));
    std::thread::sleep(Duration::from_millis(2000));
    let behind = status(&mut radicled);
    assert!(radicled.logs_times(WAITS, 4, READ_TIMEOUT));
    assert!(!radicled.any_within(behind, Duration::from_millis(2000)));
    assert_eq!(code(&radicled.reply(waiting)), "deadline");
    assert!(admitted.elapsed() >= Duration::from_secs(8));
    assert_eq!(
        radicled.read_reply(behind).unwrap(),
        br#"{"connectedPeers":0}"#
    );
    assert!(!radicled.any_within(waiting, Duration::from_millis(500)));
    // The held body still waits for credit: the stop ends it.
    assert!(!radicled.any_within(held, Duration::ZERO));
    shut_down(&mut radicled, &dirs.home);
}

/// The composed ops of a repository, by name, and whether each is a COB
/// op.
fn composed_ops(rid: RepoId, revision: &str) -> Vec<(&'static str, Value, bool)> {
    let r = rid.to_string();
    let page = json!({ "rid": r, "status": null, "page": null, "per_page": null });
    vec![
        ("issue", json!({ "rid": r, "issue_id": "abcdef0" }), true),
        ("patch", json!({ "rid": r, "patch_id": "abcdef0" }), true),
        ("issues_page", page.clone(), true),
        ("patches_page", page, true),
        ("remotes", json!({ "rid": r }), false),
        (
            "repo_stats",
            json!({ "rid": r, "revision": revision }),
            false,
        ),
        (
            "readme_at",
            json!({ "rid": r, "revision": revision }),
            false,
        ),
        ("repo_meta", json!({ "rid": r }), false),
    ]
}

/// 0008, "Methods" ("The repair fence") and "Errors" (`quarantined`): a
/// repository quarantined for its cache answers its composed COB ops
/// (`issue`, `patch`, `issues_page`, `patches_page`) `quarantined`, with
/// the record's kind and step, and its other composed reads; one
/// quarantined for a namespace answers every op naming it `quarantined`.
/// `repos_meta` and `node_info` list both, as the listings do.
#[test]
fn a_quarantined_repository_is_refused_as_0008_says() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let files: &[(&str, &[u8])] = &[("README.md", b"# Q\n")];
    let (cache, commits) = fixture::repository_with(&dirs.home, &CREATOR, "cache", &[files]);
    let (namespace, ns_commits) =
        fixture::repository_with(&dirs.home, &CREATOR, "namespace", &[files]);
    fixture::quarantine(&dirs.home, cache, Kind::Cache);
    fixture::quarantine(&dirs.home, namespace, Kind::Namespace);
    let mut radicled = served(&dirs, &[]);
    for (op, args, cob) in composed_ops(cache, &commits[0]) {
        let read = radicled.read(op, args.clone());
        if cob {
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
    for (op, args, _) in composed_ops(namespace, &ns_commits[0]) {
        let reply = radicled.read(op, args.clone()).unwrap_err();
        assert_eq!(code(&reply), "quarantined", "{op}: {reply}");
        assert_eq!(reply["error"]["data"]["kind"], "namespace", "{reply}");
    }
    let listed = read_text(&mut radicled, "repos_meta", &Value::Null);
    assert!(listed.contains(&cache.to_string()), "{listed}");
    assert!(listed.contains(&namespace.to_string()), "{listed}");
    let info: Value =
        serde_json::from_str(&read_text(&mut radicled, "node_info", &json!({}))).unwrap();
    assert_eq!(info["repos_total"], 2, "{info}");
    shut_down(&mut radicled, &dirs.home);
}

const STARTED: &str = "test hook: the write has started";
const RETURNED: &str = "test hook: the write has returned";
const QUEUED: &str = "an online repair is queued";
const HOLDS: &str = "test hook: a repair turn holds the node";
const DONE: &str = "an online repair is done";
const RECORDED: &str = "test hook: the repair's end is recorded";

/// 0008, "Methods" ("The repair fence") and "Writes": a repository's
/// composed COB ops answer `stopped` while a COB write to it is past its
/// start and not yet proven, and while its online repair runs; its other
/// composed reads go on. Once the write is proven, or the repair is over,
/// they read what it left.
///
/// Nothing here races a hold: each write is held past its start, and the
/// repair's turns before their unit, until the test releases them
/// ([`Dirs::held`]), so the fenced reads come while the write or the
/// repair is under way on any runner. The reads after the repair wait for
/// the writer to record its end, which comes a moment after its `done`.
#[test]
fn a_repository_being_written_or_repaired_fences_its_composed_cob_reads() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let (rid, commits) = fixture::repository_with(
        &dirs.home,
        &SEED,
        "fenced",
        &[&[("README.md", b"# Fenced\n")]],
    );
    let first = fixture::with_node(&dirs.home, &SEED, |node| {
        node.issues(rid).unwrap()[0].0.to_string()
    });
    let (write_hold, write_gate) = dirs.held("until", "release-write");
    let (repair_hold, repair_gate) = dirs.held("until", "release-repair");
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WRITE", &write_hold),
            ("FREEDOM_RADICLED_TEST_HOLD_REPAIR", &repair_hold),
        ],
    );
    let r = rid.to_string();
    let page = json!({ "rid": r, "status": null, "page": null, "per_page": null });
    let issue = json!({ "rid": r, "issue_id": first });
    // Its COB ops are `stopped`; `readme_at` and `remotes` go on.
    // `repo_meta` isn't fenced either, but it takes the node exclusively
    // (libradicle's `seeders`), so it waits for the write or the repair's
    // turn, which hold the node shared: it is sent last, and its answer
    // read once the test has released them.
    let fenced = |radicled: &mut Radicled| -> u64 {
        for (op, args) in [
            ("issue", issue.clone()),
            ("issues_page", page.clone()),
            ("patches_page", page.clone()),
            ("patch", json!({ "rid": r, "patch_id": "abcdef0" })),
        ] {
            let reply = radicled.read(op, args).unwrap_err();
            assert_eq!(code(&reply), "stopped", "{op}: {reply}");
        }
        for (op, args) in [
            ("readme_at", json!({ "rid": r, "revision": commits[0] })),
            ("remotes", json!({ "rid": r })),
        ] {
            assert!(radicled.read(op, args.clone()).is_ok(), "{op}");
        }
        radicled.request(
            "rad.read",
            json!({ "op": "repo_meta", "args": { "rid": r } }),
        )
    };

    // A write held past its start, then proven: proven before its reply,
    // so read at once.
    let write = radicled.request(
        "rad.write",
        json!({
            "op": "create_issue",
            "args": { "rid": r, "title": "Written", "description": "Its body.", "labels": [] },
        }),
    );
    assert!(radicled.logs(STARTED, READ_TIMEOUT));
    let meta = fenced(&mut radicled);
    assert!(!radicled.logs(RETURNED, Duration::ZERO));
    std::fs::write(&write_gate, b"").unwrap();
    assert!(radicled.reply(write)["result"]["id"].is_string());
    assert!(radicled.read_reply(meta).is_ok());
    let listed = read_text(&mut radicled, "issues_page", &page);
    assert!(listed.contains("Written"), "{listed}");
    // Its hold is over: the next write's holds until the gate is back.
    assert!(radicled.logs(RETURNED, READ_TIMEOUT));
    std::fs::remove_file(&write_gate).unwrap();

    // A write whose outcome is unknown: fenced while it runs, then while
    // its repository is repaired.
    let write = radicled.request(
        "rad.write",
        json!({
            "op": "comment_issue",
            "args": { "rid": r, "issue_id": "abcdef0123", "body": "Nowhere." },
        }),
    );
    assert!(radicled.logs_times(STARTED, 2, READ_TIMEOUT));
    assert_eq!(
        code(&radicled.read("issue", issue.clone()).unwrap_err()),
        "stopped"
    );
    std::fs::write(&write_gate, b"").unwrap();
    assert_eq!(code(&radicled.reply(write)), "outcome_unknown");
    assert!(radicled.logs(QUEUED, READ_TIMEOUT));
    // Its first turn has begun the repair, and holds before its unit.
    assert!(radicled.logs(HOLDS, READ_TIMEOUT));
    let meta = fenced(&mut radicled);
    assert!(!radicled.logs(DONE, Duration::ZERO));
    std::fs::write(&repair_gate, b"").unwrap();
    assert!(radicled.read_reply(meta).is_ok());
    assert!(radicled.logs(DONE, READ_TIMEOUT));
    assert!(radicled.logs(RECORDED, READ_TIMEOUT));
    assert!(radicled.read("issue", issue).is_ok());
    let listed = read_text(&mut radicled, "issues_page", &page);
    assert!(listed.contains("Written"), "{listed}");
    shut_down(&mut radicled, &dirs.home);
}
