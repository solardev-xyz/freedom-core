//! Replays vectors/dweb-verify-plans.json (design 0009, Verify plans and
//! Strict mode): every dweb.json case whose plan 0006 accepts, on its
//! external backend with verification and strict mode in four forms, gives
//! the recorded plan; and validate_plan gives every validation case its
//! verdict. The vectors are the design's, composed by the JS generator
//! from the reference's fetch plans.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeSet, HashMap};

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
            Plan::Error(_) => "error",
        });
    }
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        ["error", "fetch", "redirect", "strict", "verify"]
    );
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
