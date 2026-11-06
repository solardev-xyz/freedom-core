use std::io::Write as _;

use serde_json::{Value as J, json};

use super::*;
use crate::reads::not_found;

/// The composed reads' vectors, recorded from main's own code at the
/// reference (`vectors/generator/radicle-reads.js`).
const VECTORS: &str = include_str!("../../../../../vectors/radicle-reads.json");

fn cases() -> Vec<J> {
    let vectors: J = serde_json::from_str(VECTORS).unwrap();
    vectors["cases"].as_array().unwrap().clone()
}

/// What the case's scripted add-on answers `export(args)`: its text, or its
/// error payload's message, which main throws.
fn answer(case: &J, export: &str, args: J) -> Result<String, String> {
    let entry = case["addon"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["export"] == export && e["args"] == args)
        .unwrap_or_else(|| panic!("{}: no {export}({args})", case["id"]));
    let text = entry["text"].as_str().unwrap().to_string();
    match serde_json::from_str::<J>(&text) {
        Ok(J::Object(o))
            if o.get("error")
                .is_some_and(|e| e.as_str().is_some_and(|e| !e.is_empty())) =>
        {
            Err(o["error"].as_str().unwrap().to_string())
        }
        _ => Ok(text),
    }
}

/// A libradicle failure, as the service answers it.
fn failed(message: String) -> (ErrorCode, String) {
    let code = if not_found(&message) {
        ErrorCode::NotFound
    } else {
        ErrorCode::Failed
    };
    (code, message)
}

/// `repo_meta` of `rid`, from the case's answers, as the service composes
/// it.
fn meta(case: &J, rid: &J, out: &mut Vec<u8>) -> Result<(), (ErrorCode, String)> {
    let info = answer(case, "repoInfo", json!([rid])).map_err(failed)?;
    let seeders = answer(case, "seeders", json!([rid])).ok();
    let seeding = match &seeders {
        Some(text) => Seeding::Answered(js::parse(text.as_bytes()).unwrap()),
        None => Seeding::Failed,
    };
    js::repo_meta(
        js::parse(info.as_bytes()).unwrap(),
        seeding,
        out,
        &mut Work::new(REPO_INFO),
    )
    .unwrap();
    Ok(())
}

/// What the service's composition writes for the case's op, from its
/// scripted answers, as each op of `super` composes it.
fn replay(case: &J) -> Result<Vec<u8>, (ErrorCode, String)> {
    let args = &case["args"];
    let rid = &args["rid"];
    let mut out = Vec::new();
    // Through the service's own: into a reply's writer.
    let again = |text: Result<String, String>, out: &mut Vec<u8>| {
        let text = text.map_err(failed)?;
        let until = Until::new(
            std::time::Instant::now() + std::time::Duration::from_secs(60),
            libradicle::CancelToken::new(),
        );
        let mut json = Json::new(
            Budget::new(crate::output::BUDGET),
            until,
            crate::output::JSON,
        );
        super::again(&mut json, text.as_bytes()).unwrap();
        for chunk in json.end(Ok(())).unwrap() {
            out.extend_from_slice(chunk.as_slice());
        }
        Ok::<_, (ErrorCode, String)>(())
    };
    match case["op"].as_str().unwrap() {
        "readme_at" => {
            let revision = &args["revision"];
            let tree = answer(case, "treeAt", json!([rid, revision, ""])).map_err(failed)?;
            let tree: J = serde_json::from_str(&tree).unwrap();
            let blobs: Vec<&str> = tree["entries"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["kind"] == "blob")
                .map(|e| e["name"].as_str().unwrap())
                .collect();
            let Some(path) = js::readme(blobs.iter().copied()) else {
                return Err((ErrorCode::NotFound, "no readme".into()));
            };
            let blob = answer(case, "blobAt", json!([rid, revision, path])).map_err(failed)?;
            let mut spliced = js::Spliced::new(&mut out, path);
            spliced.write_all(blob.as_bytes()).unwrap();
            spliced.finish().unwrap();
        }
        "repo_meta" => meta(case, rid, &mut out)?,
        "repos_meta" => {
            let list = answer(case, "listRepos", json!([])).map_err(failed)?;
            let list: J = serde_json::from_str(&list).unwrap();
            out.push(b'[');
            for (n, repo) in list.as_array().unwrap().iter().enumerate() {
                if n > 0 {
                    out.push(b',');
                }
                meta(case, &repo["rid"], &mut out)?;
            }
            out.push(b']');
        }
        op @ ("issues_page" | "patches_page") => {
            let export = if op == "issues_page" {
                "issues"
            } else {
                "patches"
            };
            let text = answer(case, export, json!([rid])).map_err(failed)?;
            js::page(
                js::parse(text.as_bytes()).unwrap(),
                args["status"].as_str(),
                js::window(args["page"].as_str(), args["per_page"].as_str()),
                &mut out,
                &mut Work::new(TODAYS),
            )
            .unwrap();
        }
        "issue" => again(
            answer(case, "issue", json!([rid, args["issue_id"]])),
            &mut out,
        )?,
        "patch" => again(
            answer(case, "patch", json!([rid, args["patch_id"]])),
            &mut out,
        )?,
        "remotes" => again(answer(case, "remotes", json!([rid])), &mut out)?,
        "repo_stats" => again(
            answer(case, "repoStats", json!([rid, args["revision"]])),
            &mut out,
        )?,
        op => panic!("no op {op}"),
    }
    Ok(out)
}

/// 0008, "JSON results" and "Tests first": each composed op, and each of
/// main's serialization, writes what main's own code at the reference
/// answers, byte for byte; and fails as main does, with its message, each
/// code main's status: 404 for `not_found`, 500 for `failed` (the listing
/// answers 500 for either).
#[test]
fn each_composition_writes_mains_bytes() {
    let mut checked = 0;
    for case in cases() {
        let op = case["op"].as_str().unwrap();
        if op == "node_info" {
            continue;
        }
        let id = &case["id"];
        let main = &case["main"];
        match replay(&case) {
            Ok(body) => {
                assert_eq!(main["status"], 200, "{id}: {main}");
                let body = String::from_utf8(body).unwrap();
                assert_eq!(main["body"].as_str().unwrap(), body, "{id}");
            }
            Err((code, message)) => {
                let status = match code {
                    _ if op == "repos_meta" => 500,
                    ErrorCode::NotFound => 404,
                    _ => 500,
                };
                assert_eq!(main["status"], status, "{id}: {code:?} {message}");
                let body: J = serde_json::from_str(main["body"].as_str().unwrap()).unwrap();
                assert_eq!(body, json!({ "error": message }), "{id}");
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 144);
}

/// 0008, "Methods": `node_info`'s body is the design's, and main's two
/// callers rebuild their answers from it (the generator checks those
/// against the reference's).
#[test]
fn node_info_is_the_designs() {
    let mut checked = 0;
    for case in cases().iter().filter(|c| c["op"] == "node_info") {
        let expect = &case["expect"];
        let status = answer(case, "status", json!([]));
        let status = match status {
            Err(message) => {
                assert_eq!(
                    expect["error"]["message"],
                    message.as_str(),
                    "{}",
                    case["id"]
                );
                checked += 1;
                continue;
            }
            Ok(status) => serde_json::from_str::<J>(&status).unwrap(),
        };
        let peers = usize::try_from(status["connectedPeers"].as_u64().unwrap()).unwrap();
        let listed = answer(case, "listRepos", json!([])).map(|list| {
            serde_json::from_str::<J>(&list)
                .unwrap()
                .as_array()
                .unwrap()
                .len()
        });
        let mut out = Vec::new();
        write_node_info(
            &mut out,
            peers,
            listed.as_ref().map(|n| *n).map_err(String::as_str),
        )
        .unwrap();
        assert_eq!(
            expect["body"].as_str().unwrap(),
            String::from_utf8(out).unwrap(),
            "{}",
            case["id"]
        );
        checked += 1;
    }
    assert_eq!(checked, 4);
}

/// The vectors cover what the service relies on: every op answers and
/// fails, an integer past 2^53, a branch named as an index, a repeated key,
/// each README candidate.
#[test]
fn the_vectors_cover_the_compositions() {
    let cases = cases();
    let bodies = |op: &str| -> Vec<String> {
        cases
            .iter()
            .filter(|c| c["op"] == op && c["main"]["status"] == 200)
            .map(|c| c["main"]["body"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(
        bodies("remotes")
            .iter()
            .any(|b| b.contains("\"heads\":{\"0\":"))
    );
    assert!(
        bodies("issue")
            .iter()
            .any(|b| b.contains("9007199254740992"))
    );
    assert!(
        bodies("issues_page")
            .iter()
            .any(|b| b.contains("18446744073709552000"))
    );
    for candidate in js::README {
        assert!(
            bodies("readme_at")
                .iter()
                .any(|b| b.ends_with(&format!(",\"path\":\"{candidate}\"}}"))),
            "{candidate}"
        );
    }
    assert!(cases.iter().any(|c| c["id"] == "remotes-repeated-keys"));
}

/// A captured text is held at its limit, and one byte past it is
/// `too_large`; what is held is exactly the text.
#[test]
fn a_text_is_captured_up_to_its_limit() {
    let write = |w: &mut dyn io::Write| -> json::Written {
        w.write_all(b"[1,2,3]").map_err(serde_json::Error::io)
    };
    let text = capture(7, write).unwrap();
    assert_eq!(text, b"[1,2,3]");
    assert_eq!(text.capacity(), 7);
    match capture(6, write) {
        Err(Failure::Refused(Refused::TooLarge { size, limit })) => {
            assert_eq!((size, limit), (7, 6));
        }
        other => panic!("{other:?}"),
    }
    // A serializer's own error stays its own.
    let broken = |_: &mut dyn io::Write| -> json::Written {
        Err(serde_json::Error::io(io::Error::other("broken")))
    };
    assert!(matches!(capture(7, broken), Err(Failure::Json(_))));
}

/// The bounds' figures (0008, "Pools and budgets"): a walk gets the
/// add-on's, `repo_info` a quarter of the built budget.
#[test]
fn the_figures() {
    assert_eq!(TODAYS, libradicle::BINDING_READ_BUDGET);
    assert_eq!(TODAYS, 16 << 20);
    assert_eq!(REPO_INFO, 8 << 20);
    let until = Until::new(std::time::Instant::now(), libradicle::CancelToken::new());
    let walk = bounds(&until, TODAYS);
    assert_eq!((walk.budget, walk.loads), (TODAYS, TODAYS));
    until.cancel.cancel();
    assert!(walk.cancel.is_cancelled());
}
