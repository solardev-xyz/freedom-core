//! Replays vectors/dweb-verify-plans.json (design 0009, Verify plans and
//! Strict mode): every dweb.json case whose plan 0006 accepts, on its
//! external backend with verification and strict mode in four forms, gives
//! the recorded plan; and validate_plan gives every validation case its
//! verdict. The vectors are the design's, composed by the JS generator
//! from the reference's fetch plans.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeSet, HashMap};

use fc_dweb::verifier::{MAX_PATH, Method, Options, Verifier};
use fc_dweb::{Backend, Opening, Plan, PlanRequest, Request, Resolved, open, validate_plan};
use fc_json::JsValue;
use serde_json::Value as Json;

fn vectors() -> Json {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/dweb-verify-plans.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn id(entry: &Json) -> &str {
    entry["id"].as_str().unwrap_or("?")
}

fn js_value(value: &Json) -> JsValue {
    fc_json::parse(&value.to_string()).unwrap()
}

fn pairs(value: &Json) -> Vec<(String, String)> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p[0].as_str().unwrap().to_owned(),
                p[1].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// The backend as `dweb.open` reads it, written back the same (as JSON:
/// the file's reader doesn't keep key order).
fn backend(request: &Json) -> Backend {
    let value = js_value(&request["backend"]);
    let backend = Backend::from_value(&value).unwrap_or_else(|| panic!("{request}"));
    let written: Json = serde_json::from_str(&backend.to_value().stringify()).unwrap();
    assert_eq!(written, request["backend"], "{request}");
    backend
}

fn plan_json(plan: &Plan) -> Json {
    serde_json::from_str(&plan.to_json()).unwrap()
}

/// The plan for a request, through the resolution it scripts.
fn plan_for(entry: &Json) -> Plan {
    let request = &entry["request"];
    let headers = pairs(&request["headers"]);
    let opening = open(&Request {
        url: request["url"].as_str().unwrap(),
        method: request["method"].as_str().unwrap(),
        headers: &headers,
        backend: backend(request),
    })
    .unwrap_or_else(|e| panic!("{}: {e}", id(entry)));
    match opening {
        // A case's resolution is scripted whether or not the handler
        // reaches the lookup.
        Opening::Plan(plan) => plan,
        Opening::Resolve(pending) => {
            let resolution = &entry["resolution"];
            let value;
            let resolved = if let Some(message) = resolution.get("threw") {
                Resolved::Threw(message.as_str().unwrap())
            } else {
                value = js_value(&resolution["value"]);
                Resolved::Returned(&value)
            };
            pending
                .finish(resolved)
                .unwrap_or_else(|e| panic!("{}: {e}", id(entry)))
        }
    }
}

#[test]
fn constants() {
    let c = &vectors()["constants"];
    let names = |v: &Json| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        names(&c["verify_headers"]["ant"]),
        fc_dweb::VERIFY_HEADERS_ANT
    );
    assert_eq!(
        names(&c["verify_headers"]["ipfs"]),
        fc_dweb::VERIFY_HEADERS_IPFS
    );
    let ops = |ops: &[fc_dweb::ResponseOp]| -> Vec<String> {
        ops.iter().map(|o| o.as_str().to_owned()).collect()
    };
    use fc_dweb::ResponseOp::{CanonicalizeRedirect, StripPageState};
    assert_eq!(
        names(&c["verify_response_operations"]["ant"]),
        ops(&[CanonicalizeRedirect, StripPageState])
    );
    assert_eq!(
        names(&c["verify_response_operations"]["ipfs"]),
        ops(&[StripPageState])
    );
    let m = &c["strict_messages"];
    for (key, text) in [
        ("off", fc_dweb::STRICT_OFF),
        ("unsupported", fc_dweb::STRICT_UNSUPPORTED),
        ("dnslink", fc_dweb::STRICT_DNSLINK),
        ("key", fc_dweb::STRICT_KEY),
        ("encrypted", fc_dweb::STRICT_ENCRYPTED),
    ] {
        assert_eq!(m[key], text, "{key}");
    }
    let b = &c["verify_bound"];
    assert_eq!(b["max_path"], MAX_PATH);
    for (key, status, text) in [
        (
            "url",
            fc_dweb::VERIFY_URL_STATUS,
            fc_dweb::VERIFY_URL_TOO_LONG,
        ),
        (
            "header",
            fc_dweb::VERIFY_HEADER_STATUS,
            fc_dweb::VERIFY_HEADER_TOO_LARGE,
        ),
    ] {
        assert_eq!(
            b[key],
            serde_json::json!({ "status": status, "code": status, "message": text }),
            "{key}"
        );
    }
}

#[test]
fn requests() {
    let vectors = vectors();
    let entries = vectors["requests"].as_array().unwrap();
    assert!(entries.len() >= 1000);
    let mut kinds = BTreeSet::new();
    for entry in entries {
        let plan = plan_for(entry);
        assert_eq!(plan_json(&plan), entry["plan"], "{}", id(entry));
        kinds.insert(match plan {
            Plan::Fetch(_) => "fetch",
            Plan::Verify(_) => "verify",
            Plan::Redirect(_) => "redirect",
            Plan::Error(e) if e.status == fc_dweb::STRICT_STATUS => "strict",
            Plan::Error(e)
                if [fc_dweb::VERIFY_URL_STATUS, fc_dweb::VERIFY_HEADER_STATUS]
                    .contains(&e.status) =>
            {
                "bound"
            }
            Plan::Error(_) => "error",
        });
    }
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        ["bound", "error", "fetch", "redirect", "strict", "verify"]
    );
}

/// Whether `dweb.verify` takes a verify plan: its check, as the core runs
/// it again (0009, `dweb.verify`).
fn verified(plan: &fc_dweb::Verify, method: &str) -> Result<(), fc_dweb::Refusal> {
    let method = match method.to_ascii_uppercase().as_str() {
        "HEAD" => Method::Head,
        _ => Method::Get,
    };
    Verifier::new(1, plan, method, None, false, Options::default()).map(|_| ())
}

/// Every plan `dweb.open` makes that main takes is one `dweb.verify` takes
/// too: each verify plan main's validation passes is accepted by the
/// core's check, the verifier's bound's cases (`*-bound-*`) included, and
/// the verifier's 414 and 431 are planned only there, in place of a verify
/// plan past the bound (0009, Bounds).
#[test]
fn every_verify_plan_dweb_open_makes_is_one_dweb_verify_takes() {
    let vectors = vectors();
    let (mut verify, mut bound) = (0, BTreeSet::new());
    for entry in vectors["requests"].as_array().unwrap() {
        let id = id(entry);
        let at_bound = id.contains("-bound-");
        match plan_for(entry) {
            Plan::Verify(plan) if entry["validation"] == "valid" => {
                let method = entry["request"]["method"].as_str().unwrap();
                assert_eq!(verified(&plan, method), Ok(()), "{id}");
                verify += 1;
                if at_bound {
                    bound.insert("verify");
                }
            }
            Plan::Error(e) if e.status == fc_dweb::VERIFY_URL_STATUS => {
                assert!(at_bound, "{id}");
                assert_eq!(e.message, fc_dweb::VERIFY_URL_TOO_LONG, "{id}");
                bound.insert("414");
            }
            Plan::Error(e) if e.status == fc_dweb::VERIFY_HEADER_STATUS => {
                assert!(at_bound, "{id}");
                assert_eq!(e.message, fc_dweb::VERIFY_HEADER_TOO_LARGE, "{id}");
                bound.insert("431");
            }
            plan => assert!(!at_bound, "{id}: {plan:?}"),
        }
    }
    assert!(verify > 200, "{verify}");
    assert_eq!(
        bound.into_iter().collect::<Vec<_>>(),
        ["414", "431", "verify"]
    );
}

/// Strict mode changes nothing at the verifier's bound: each request past
/// it in strict mode (`*-bound-*-strict`) gets the 414 or 431, with its
/// message, that the same request gets without strict mode, never strict
/// mode's 403 (0009, Verify plans).
#[test]
fn strict_mode_changes_no_plan_past_the_bound() {
    let vectors = vectors();
    let requests: HashMap<&str, &Json> = vectors["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (id(e), e))
        .collect();
    let mut statuses = BTreeSet::new();
    for (&id, &entry) in &requests {
        let Some(plain) = id
            .strip_suffix("-strict")
            .filter(|_| id.contains("-bound-"))
        else {
            continue;
        };
        let plain = requests[plain];
        let mut request = plain["request"].clone();
        request["backend"]["strict"] = true.into();
        assert_eq!(entry["request"], request, "{id}");
        assert_eq!(entry["plan"], plain["plan"], "{id}");
        let plan = plan_for(entry);
        assert_eq!(plan_json(&plan), plan_json(&plan_for(plain)), "{id}");
        match plan {
            Plan::Error(e) => statuses.insert(e.status),
            plan => panic!("{id}: {plan:?}"),
        };
    }
    assert_eq!(
        statuses.into_iter().collect::<Vec<_>>(),
        [fc_dweb::VERIFY_URL_STATUS, fc_dweb::VERIFY_HEADER_STATUS]
    );
}

/// The plan `dweb.open` makes for `url`, with `headers`, on an external
/// backend whose verification is on, in strict mode or not.
fn opened(url: &str, headers: &[(String, String)], strict: bool) -> Plan {
    let node = if url.starts_with("bzz:") {
        "ant"
    } else {
        "ipfs"
    };
    let mode = if node == "ant" { "external" } else { "gateway" };
    let mut backend = serde_json::json!({ node: mode, "up": true, "verify": true });
    if strict {
        backend["strict"] = true.into();
    }
    let backend = Backend::from_value(&js_value(&backend)).unwrap();
    match open(&Request {
        url,
        method: "GET",
        headers,
        backend,
    })
    .unwrap()
    {
        Opening::Plan(plan) => plan,
        Opening::Resolve(_) => panic!("{url}: a lookup"),
    }
}

/// At the verifier's bound and on each side of it, for each root and each
/// thing it bounds, `dweb.open` plans a verify plan `dweb.verify` takes, or
/// the 414 or 431 in its place, never a plan `dweb.verify` refuses: the
/// path below the root; a Swarm plan's path and query together; an IPFS or
/// IPNS query, which isn't counted, at any length up to 0006's 64 KiB URL;
/// and each kept header's value. Strict mode or not, the plan is the same,
/// to the 414's or 431's message.
#[test]
fn dweb_open_plans_only_what_dweb_verify_takes_at_the_bound() {
    let swarm = "c0ffee".repeat(10) + "beef";
    let cid = "bafybeidon73zkcrwdb5iafqtijxildoonbwnpv7dyd6ef3qdgads2jc4su";
    let name = "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8";
    let path = |n: usize| format!("/{}", "p".repeat(n - 1));
    let query = |n: usize| format!("?{}", "q".repeat(n - 1));
    let range = |n: usize| vec![("Range".to_owned(), format!("bytes={}-", "0".repeat(n - 7)))];
    let tag = |n: usize| {
        vec![(
            "If-None-Match".to_owned(),
            format!("\"{}\"", "t".repeat(n - 2)),
        )]
    };
    let url = |scheme: &str, root: &str, rest: String| format!("{scheme}://{root}{rest}");
    // What, the URL, its headers, and the status past the bound, if any.
    type Case = (String, String, Vec<(String, String)>, Option<u16>);
    let mut cases: Vec<Case> = vec![];
    let near = [MAX_PATH - 1, MAX_PATH, MAX_PATH + 1];
    for (scheme, root) in [("bzz", swarm.as_str()), ("ipfs", cid), ("ipns", name)] {
        for n in near {
            let past = (n > MAX_PATH).then_some(fc_dweb::VERIFY_URL_STATUS);
            cases.push((
                format!("{scheme} path {n}"),
                url(scheme, root, path(n)),
                vec![],
                past,
            ));
            let split = url(scheme, root, path(n - 16) + &query(16));
            let past = past.filter(|_| scheme == "bzz");
            cases.push((format!("{scheme} path and query {n}"), split, vec![], past));
            let header = (n > MAX_PATH).then_some(fc_dweb::VERIFY_HEADER_STATUS);
            cases.push((
                format!("{scheme} range {n}"),
                url(scheme, root, "/a".into()),
                range(n),
                header,
            ));
            if scheme != "bzz" {
                let tagged = url(scheme, root, "/a".into());
                cases.push((format!("{scheme} tag {n}"), tagged, tag(n), header));
            }
        }
        if scheme != "bzz" {
            // A short path, and a path at the bound, with a query to the
            // URL's 64 KiB.
            for p in [2, MAX_PATH] {
                let head = url(scheme, root, path(p));
                let rest = (64 << 10) - head.len();
                cases.push((
                    format!("{scheme} path {p}, query to 64 KiB"),
                    head + &query(rest),
                    vec![],
                    None,
                ));
            }
        }
    }
    let message = |status| match status {
        fc_dweb::VERIFY_URL_STATUS => fc_dweb::VERIFY_URL_TOO_LONG,
        _ => fc_dweb::VERIFY_HEADER_TOO_LARGE,
    };
    for (what, url, headers, past) in cases {
        assert!(url.len() <= 64 << 10, "{what}");
        // Strict mode or not, the same plan, to its message.
        let plans = [false, true].map(|strict| opened(&url, &headers, strict));
        assert_eq!(plan_json(&plans[1]), plan_json(&plans[0]), "{what}");
        for (strict, plan) in [false, true].into_iter().zip(plans) {
            match (plan, past) {
                (Plan::Verify(plan), None) => {
                    assert_eq!(verified(&plan, "GET"), Ok(()), "{what}, strict {strict}");
                }
                (Plan::Error(e), Some(status)) => assert_eq!(
                    (e.status, e.message.as_str()),
                    (status, message(status)),
                    "{what}, strict {strict}"
                ),
                (plan, past) => panic!("{what}, strict {strict}: {plan:?}, expected {past:?}"),
            }
        }
    }
}

#[test]
fn validation() {
    let vectors = vectors();
    let requests: HashMap<&str, &Json> = vectors["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (id(e), e))
        .collect();
    let mut seen = BTreeSet::new();
    for entry in vectors["validation"].as_array().unwrap() {
        assert_eq!(entry["source"], "design");
        let (request, plan) = match entry["request_id"].as_str() {
            Some(rid) => (&requests[rid]["request"], &requests[rid]["plan"]),
            None => (&entry["request"], &entry["plan"]),
        };
        let got = validate_plan(
            &js_value(plan),
            &PlanRequest {
                url: request["url"].as_str().unwrap(),
                method: request["method"].as_str().unwrap(),
                backend: backend(request),
            },
        );
        let got = match got {
            Ok(()) => "valid",
            Err(refusal) => refusal.as_str(),
        };
        assert_eq!(got, entry["expect"].as_str().unwrap(), "{}", id(entry));
        seen.insert(got);
    }
    // Every stage a verify plan or strict mode adds is exercised.
    for reason in [
        "valid", "shape", "node", "root", "path", "query", "header", "retry", "timers", "response",
        "trust", "error",
    ] {
        assert!(seen.contains(reason), "no vector for {reason}");
    }
}

/// Every verify plan of the vectors, as main sends it back in
/// `dweb.verify`, reads as the plan it was, and writes back the same.
#[test]
fn verify_plans_read_back_as_written() {
    let v = vectors();
    let mut n = 0;
    for entry in v["requests"].as_array().unwrap() {
        let plan = &entry["plan"];
        if plan.get("verify").is_none() {
            continue;
        }
        let read = fc_dweb::Verify::from_value(&js_value(plan))
            .unwrap_or_else(|| panic!("{}: not read", id(entry)));
        assert_eq!(plan_json(&Plan::Verify(read)), *plan, "{}", id(entry));
        n += 1;
    }
    assert_eq!(n, 256, "{n}");
}

/// A change to a plan's JSON.
type Edit = Box<dyn Fn(&mut Json)>;

/// Anything but the shape `dweb.open` writes is refused: a member missing
/// or added, a value of another type or out of range.
#[test]
fn a_verify_plan_of_another_shape_reads_as_nothing() {
    let v = vectors();
    let plan = v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["plan"])
        .find(|p| p.get("verify").is_some())
        .unwrap()
        .clone();
    assert!(fc_dweb::Verify::from_value(&js_value(&plan)).is_some());
    let edits: Vec<Edit> = vec![
        Box::new(|p| p["extra"] = Json::Bool(true)),
        Box::new(|p| p["verify"]["extra"] = Json::Bool(true)),
        Box::new(|p| {
            p["verify"].as_object_mut().unwrap().remove("query");
        }),
        Box::new(|p| p["verify"]["node"] = "bee".into()),
        Box::new(|p| p["verify"]["root"] = serde_json::json!({ "swarm": "a", "ipfs": "b" })),
        Box::new(|p| p["verify"]["root"] = serde_json::json!({ "bzz": "a" })),
        Box::new(|p| p["verify"]["path"] = 1.into()),
        Box::new(|p| p["verify"]["headers"] = serde_json::json!([["range"]])),
        Box::new(|p| p["verify"]["retry"]["attempts"] = 1.5.into()),
        Box::new(|p| p["verify"]["retry"]["attempts"] = (-1).into()),
        Box::new(|p| p["verify"]["retry"]["statuses"] = serde_json::json!([70000])),
        Box::new(|p| p["verify"]["retry"]["on_error"] = 1.into()),
        Box::new(|p| p["verify"]["timers"]["body_idle_ms"] = Json::Null),
        Box::new(|p| p["verify"]["response"] = serde_json::json!(["strip_everything"])),
        Box::new(|p| p["verify"]["trust"]["content"] = "trusted".into()),
        Box::new(|p| p["verify"]["trust"]["name"] = 1.into()),
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut changed = plan.clone();
        edit(&mut changed);
        assert!(
            fc_dweb::Verify::from_value(&js_value(&changed)).is_none(),
            "{i}: {changed}"
        );
    }
}
