//! The import against `vectors/radicle-import.json`: what main sends
//! parses as `rad.import_repo`'s params, field for field; a proven import
//! answers the add-on's `{ rid }` text byte for byte; and each of the
//! service's errors has the code and message the vectors pin, whose text
//! main reads. Then the error mapping and the params on their own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::*;

const VECTORS: &str = include_str!("../../../../vectors/radicle-import.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

/// A home with `config.json` and a working copy with one commit on
/// `master`, for libradicle's own texts.
fn home_and_work() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.json"),
        r#"{"preferredSeeds":[],"node":{"alias":"vectors","network":"test","peers":{"type":"static"}}}"#,
    )
    .unwrap();
    let work = dir.path().join("work");
    let repo = radicle::git::raw::Repository::init(&work).unwrap();
    std::fs::write(work.join("README.md"), "x").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("README.md")).unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = radicle::git::raw::Signature::now("V", "v@example.invalid").unwrap();
    repo.commit(
        Some("refs/heads/master"),
        &signature,
        &signature,
        "x",
        &tree,
        &[],
    )
    .unwrap();
    (dir, home, work)
}

/// The service's answer for the vectors' error case `id`.
fn service_error(id: &str, vectors: &Value) -> ErrorBody {
    let rid: radicle::prelude::RepoId = vectors["constants"]["rid"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    match id {
        "error-exists" => refusal(libradicle::Error::Exists(rid)),
        "error-outcome-unknown" => outcome_unknown(),
        "error-needs-vault" => needs_vault(),
        "error-unsupported-layout" => {
            let dir = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(dir.path()).unwrap();
            let why =
                roots::check(std::slice::from_ref(&root), &[root.join("inside")]).unwrap_err();
            ErrorBody::new(ErrorCode::UnsupportedLayout, why.0)
        }
        "error-no-branch" => {
            // libradicle's own text, from a working copy without `main`.
            let (_dir, home, work) = home_and_work();
            let key = radicle::crypto::SigningKey::from_seed(radicle::crypto::Seed::new([1; 32]));
            let e = libradicle::import::Import::prepare(&home, &key, &work, "n", "", "main")
                .unwrap_err();
            refusal(e)
        }
        "error-params" => ErrorBody::new(ErrorCode::InvalidArgument, PARAMS),
        "error-path" => ErrorBody::new(ErrorCode::InvalidArgument, NOT_THE_SOURCE),
        "error-already-called" => ErrorBody::new(ErrorCode::InvalidArgument, ALREADY_CALLED),
        "error-before-reconcile" => ErrorBody::new(ErrorCode::Stopped, BEFORE_RECONCILE),
        "error-ending" => ErrorBody::new(ErrorCode::Stopped, ENDING),
        "error-not-a-repository" => {
            // libgit2's error as git2 shows it, through today's test.
            let path = format!(
                "{}/freedom-browser",
                vectors["constants"]["temp"].as_str().unwrap()
            );
            refusal(libradicle::Error::Git(radicle::git::raw::Error::new(
                radicle::git::raw::ErrorCode::NotFound,
                radicle::git::raw::ErrorClass::Repository,
                format!("could not find repository at '{path}'"),
            )))
        }
        other => panic!("no service error for {other}"),
    }
}

#[test]
fn every_vector_replays() {
    let vectors = vectors();
    let imports = vectors["imports"].as_array().unwrap();
    assert!(imports.len() >= 15);
    let mut errors = 0;
    for case in imports {
        let id = case["id"].as_str().unwrap();
        // What main sends, as `rad.import_repo`'s params.
        let args = case["addon"]["args"].as_array().unwrap();
        let sent = json!({
            "path": args[0], "name": args[1], "description": args[2], "default_branch": args[3],
        });
        let params = parse_params(&serde_json::value::to_raw_value(&sent).unwrap()).unwrap();
        assert_eq!(
            [
                params.path.as_str(),
                &params.name,
                &params.description,
                &params.default_branch
            ],
            [
                args[0].as_str().unwrap(),
                args[1].as_str().unwrap(),
                args[2].as_str().unwrap(),
                args[3].as_str().unwrap()
            ],
            "{id}"
        );
        let expect = &case["expect"];
        if let Some(text) = expect["result_text"].as_str() {
            let rid = serde_json::from_str::<Value>(text).unwrap()["rid"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(result(&rid).get(), text, "{id}");
            assert_eq!(case["addon"]["text"], text, "{id}");
        }
        if expect["error"].is_object() {
            errors += 1;
            let answered = service_error(id, &vectors);
            assert_eq!(
                serde_json::to_value(answered.code).unwrap(),
                expect["error"]["code"],
                "{id}"
            );
            assert_eq!(answered.message, expect["error"]["message"], "{id}");
            // And main read that text, as the add-on's error.
            assert_eq!(
                case["addon"]["text"],
                json!({ "error": answered.message }).to_string(),
                "{id}"
            );
        }
    }
    assert_eq!(errors, 11);
}

#[test]
fn the_import_has_300_s() {
    assert_eq!(LIMIT, std::time::Duration::from_secs(300));
}

#[test]
fn the_error_mapping() {
    let rid: radicle::prelude::RepoId = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap();
    let invalid = refusal(libradicle::Error::InvalidImport("x".into()));
    assert_eq!(
        (invalid.code, invalid.message.as_str()),
        (ErrorCode::InvalidArgument, "x")
    );
    let exists = refusal(libradicle::Error::Exists(rid));
    assert_eq!(exists.code, ErrorCode::Failed);
    // Anything else: today's message test.
    let missing = refusal(libradicle::Error::NodeThread(
        "repository does not exist".into(),
    ));
    assert_eq!(missing.code, ErrorCode::NotFound);
    let other = refusal(libradicle::Error::NodeThread(
        "a node holds the home".into(),
    ));
    assert_eq!(other.code, ErrorCode::Failed);
    assert_eq!(outcome_unknown().code, ErrorCode::OutcomeUnknown);
    assert_eq!(needs_vault().code, ErrorCode::NeedsVault);
}

#[test]
fn params_are_four_strings_and_nothing_else() {
    let parse = |value: Value| {
        let raw = serde_json::value::to_raw_value(&value).unwrap();
        parse_params(&raw)
    };
    let ok = json!({ "path": "/w", "name": "n", "description": "", "default_branch": "main" });
    assert_eq!(
        parse(ok),
        Some(Params {
            path: "/w".into(),
            name: "n".into(),
            description: String::new(),
            default_branch: "main".into(),
        })
    );
    for bad in [
        json!({ "path": "/w", "name": "n", "description": "" }),
        json!({ "path": "/w", "name": "n", "description": "", "default_branch": "main", "x": 1 }),
        json!({ "path": 1, "name": "n", "description": "", "default_branch": "main" }),
        json!({ "path": "/w", "name": null, "description": "", "default_branch": "main" }),
        json!(["/w", "n", "", "main"]),
        json!(null),
    ] {
        assert_eq!(parse(bad.clone()), None, "{bad}");
    }
}

#[test]
fn a_source_that_isnt_unicode_grants_nothing() {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let source = Source::find(std::ffi::OsStr::from_bytes(b"/tmp/\xff"), &[]);
        assert!(source.granted().is_empty());
        assert!(source.named.is_none());
    }
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let work = root.join("work");
    std::fs::create_dir_all(work.join(".git")).unwrap();
    let source = Source::find(work.as_os_str(), &[]);
    assert_eq!(source.granted(), std::slice::from_ref(&work));
    // A protected root inside it: nothing granted, and the reason kept.
    let source = Source::find(work.as_os_str(), &[work.join(".git")]);
    assert!(source.granted().is_empty());
    assert!(source.summary()["unsupported"].is_string());
}
