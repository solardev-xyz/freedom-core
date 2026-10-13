//! Replays vectors/dweb.json, generated from the pinned protocol handlers.
//! `plan` composes the reference's outcome with the tables; its response
//! operations, trust labels and body idle bound are the design's, as is all
//! of `validation`. Entries marked `deviation` are where the core differs
//! from today by design.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_dweb::{
    Backend, BodyAction, Node, Opening, Plan, Request, Resolved, Resolver, ResponseHead, SmallText,
    SmallTextDecision, canonicalize_redirect, cid_v0_to_v1_base32, cid_v1_b58btc_to_base32,
    decode_uri_component, failure, ipns_mh_to_cid_v1_base36, is_dweb_name_host, is_ens_host,
    is_potential_ens_name, is_tezos_domain_host, join_published_path, name_system_label_for_host,
    open, relabel, respond, rewrite_gateway_location, same_segment, strip_decoded_encoding,
    strip_page_state,
};
use fc_json::JsValue;
use serde_json::Value as Json;

fn vectors() -> Json {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/dweb.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s<'a>(entry: &'a Json, key: &str) -> &'a str {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {entry}"))
}

fn id(entry: &Json) -> &str {
    entry["id"].as_str().unwrap_or("?")
}

fn arr<'a>(entry: &'a Json, key: &str) -> &'a [Json] {
    entry[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} in {entry}"))
}

/// `[[name, value], …]`.
fn pairs(value: &Json) -> Vec<(String, String)> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_owned(),
                pair[1].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// A JSON value as JavaScript sees it.
fn js_value(value: &Json) -> JsValue {
    fc_json::parse(&value.to_string()).unwrap()
}

/// `{ ant | ipfs: mode, up }`, read as `dweb.open` reads it, and written
/// back the same.
fn backend(request: &Json) -> Backend {
    let value = js_value(&request["backend"]);
    let backend = Backend::from_value(&value).unwrap_or_else(|| panic!("{request}"));
    assert_eq!(backend.to_value(), value);
    backend
}

const BUNDLED: Backend = Backend::Ant {
    mode: fc_dweb::Ant::Bundled,
    up: true,
};
const NATIVE: Backend = Backend::Ipfs {
    mode: fc_dweb::Ipfs::Native,
    up: true,
};
const GATEWAY: Backend = Backend::Ipfs {
    mode: fc_dweb::Ipfs::Gateway,
    up: true,
};

fn plan_json(plan: &Plan) -> Json {
    serde_json::from_str(&plan.to_json()).unwrap()
}

/// The plan for a request vector, through the resolver it scripts.
fn plan_for(entry: &Json) -> Plan {
    let request = &entry["request"];
    let headers = pairs(&request["headers"]);
    let opening = open(&Request {
        url: s(request, "url"),
        method: s(request, "method"),
        headers: &headers,
        backend: backend(request),
    })
    .unwrap_or_else(|e| panic!("{}: {e}", id(entry)));
    let calls = arr(&entry["js"], "resolve");
    match opening {
        Opening::Plan(plan) => {
            assert!(
                calls.is_empty(),
                "{}: the reference resolved {calls:?}",
                id(entry)
            );
            plan
        }
        Opening::Resolve(pending) => {
            assert_eq!(
                calls.len(),
                1,
                "{}: the reference resolved nothing",
                id(entry)
            );
            assert_eq!(pending.name(), s(&calls[0], "name"), "{}", id(entry));
            let resolver = match pending.resolver() {
                Resolver::Ens => "resolveEnsContent",
                Resolver::Tezos => "resolveTezosDomain",
            };
            assert_eq!(resolver, s(&calls[0], "fn"), "{}", id(entry));
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
    let vectors = vectors();
    let c = &vectors["constants"];
    let table = |backend: Backend| {
        let fetch = Plan::Fetch(fc_dweb::Fetch {
            node: Node::Ant,
            path: String::new(),
            headers: Vec::new(),
            retry: fc_dweb::retry(backend),
            timers: fc_dweb::timers(backend),
            response: Vec::new(),
            trust: fc_dweb::Trust {
                name: None,
                content: fc_dweb::content_trust(backend),
            },
        });
        plan_json(&fetch)["fetch"].clone()
    };
    for (backend, expected) in [
        (BUNDLED, &c["bzz"]),
        (NATIVE, &c["ipfs"]["native"]),
        (GATEWAY, &c["ipfs"]["gateway"]),
    ] {
        let ours = table(backend);
        assert_eq!(ours["retry"], expected["retry"], "{backend:?}");
        assert_eq!(ours["timers"], expected["timers"], "{backend:?}");
    }
    let names = |key: &Json| -> Vec<String> {
        key.as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        names(&c["bzz"]["forwarded_request_headers"]),
        fc_dweb::FORWARDED_REQUEST_HEADERS
    );
    let mut swarm: Vec<_> = fc_dweb::SWARM_HEADERS
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    swarm.sort();
    assert_eq!(pairs(&c["bzz"]["swarm_headers"]), swarm);
    let statuses: Vec<u16> = c["bzz"]["redirect_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u16)
        .collect();
    assert_eq!(statuses, fc_dweb::BZZ_REDIRECT_STATUSES);
    assert_eq!(
        names(&c["ipfs"]["stripped_request_headers"]),
        fc_dweb::STRIPPED_REQUEST_HEADERS
    );
    assert_eq!(
        names(&c["ipfs"]["known_gateway_hosts"]),
        fc_dweb::KNOWN_GATEWAY_HOSTS
    );
    assert_eq!(
        names(&c["ipfs"]["dropped_upstream_response_headers"]),
        fc_dweb::DECODED_ENCODING_HEADERS
    );
    assert_eq!(
        names(&c["page_state_response_headers"]),
        fc_dweb::PAGE_STATE_RESPONSE_HEADERS
    );
    assert_eq!(
        c["design"]["body_idle_ms"].as_u64(),
        Some(u64::from(fc_dweb::BODY_IDLE_MS))
    );
    // A node that isn't running: each mode's text, as the manager gives it.
    let not_running = &c["ipfs"]["not_running"];
    for (mode, text) in [
        ("native", fc_dweb::NATIVE_NOT_RUNNING),
        ("gateway", fc_dweb::GATEWAY_NOT_RUNNING),
    ] {
        let error = fc_dweb::ErrorPlan {
            status: 503,
            message: text.into(),
        };
        assert_eq!(s(&not_running[mode], "body"), error.body(), "{mode}");
    }
}

#[test]
fn cids() {
    let vectors = vectors();
    for entry in arr(&vectors, "cids") {
        let input = s(entry, "input");
        let expect = |key: &str| entry[key].as_str().map(str::to_owned);
        assert_eq!(
            cid_v0_to_v1_base32(input),
            expect("cid_v0_to_v1_base32"),
            "{}",
            id(entry)
        );
        assert_eq!(
            cid_v1_b58btc_to_base32(input),
            expect("cid_v1_b58btc_to_base32"),
            "{}",
            id(entry)
        );
        assert_eq!(
            ipns_mh_to_cid_v1_base36(input),
            expect("ipns_mh_to_cid_v1_base36"),
            "{}",
            id(entry)
        );
    }
}

#[test]
fn hosts() {
    let vectors = vectors();
    for entry in arr(&vectors, "hosts") {
        let host = s(entry, "host");
        let flag = |key: &str| entry[key].as_bool().unwrap();
        assert_eq!(is_ens_host(host), flag("is_ens_host"), "{host:?}");
        assert_eq!(
            is_tezos_domain_host(host),
            flag("is_tezos_domain_host"),
            "{host:?}"
        );
        assert_eq!(
            is_dweb_name_host(host),
            flag("is_dweb_name_host"),
            "{host:?}"
        );
        assert_eq!(
            is_potential_ens_name(host),
            flag("is_potential_ens_name"),
            "{host:?}"
        );
        assert_eq!(
            name_system_label_for_host(host),
            s(entry, "label"),
            "{host:?}"
        );
    }
    for entry in arr(&vectors, "published_paths") {
        assert_eq!(
            join_published_path(entry["base_path"].as_str(), s(entry, "request_path")),
            s(entry, "joined"),
            "{entry}"
        );
    }
}

#[test]
fn requests() {
    let vectors = vectors();
    let entries = arr(&vectors, "requests");
    assert!(entries.len() > 250);
    for entry in entries {
        let plan = plan_for(entry);
        assert_eq!(plan_json(&plan), entry["plan"], "{}", id(entry));
        // The reference's own outcome, not just the composed plan.
        let js = &entry["js"];
        match &plan {
            Plan::Fetch(fetch) => {
                assert_eq!(fetch.path, s(&js["fetch"], "path"), "{}", id(entry));
                assert_eq!(
                    fetch.headers,
                    pairs(&js["fetch"]["headers"]),
                    "{}",
                    id(entry)
                );
            }
            Plan::Redirect(redirect) => {
                let mut headers = redirect.headers.clone();
                headers.push(("location".into(), redirect.location.clone()));
                headers.sort();
                assert_eq!(headers, pairs(&js["redirect"]["headers"]), "{}", id(entry));
                assert_eq!(js["redirect"]["status"], 307);
            }
            Plan::Error(error) => {
                assert_eq!(error.body(), s(&js["error"], "body"), "{}", id(entry));
                assert_eq!(
                    js["error"]["status"].as_u64(),
                    Some(u64::from(error.status)),
                    "{}",
                    id(entry)
                );
                assert_eq!(
                    pairs(&js["error"]["headers"]),
                    [(
                        "content-type".to_owned(),
                        "application/json; charset=utf-8".to_owned()
                    )]
                );
            }
        }
    }
}

/// Small text over the upstream chunks: the decision and the reads it took
/// (the end of the body is a read).
fn sniff(declared: usize, chunks: &[Vec<u8>]) -> (SmallTextDecision, usize) {
    let mut sniffer = SmallText::new(declared);
    for (read, chunk) in chunks.iter().enumerate() {
        if let Some(decision) = sniffer.push(chunk.clone()) {
            return (decision, read + 1);
        }
    }
    (sniffer.finish(), chunks.len() + 1)
}

fn chunk_bytes(spec: &Json) -> Vec<u8> {
    match spec {
        Json::String(hex) => hex::decode(hex).unwrap(),
        _ => vec![
            u8::from_str_radix(s(spec, "fill"), 16).unwrap();
            spec["length"].as_u64().unwrap() as usize
        ],
    }
}

#[test]
fn exchanges() {
    let vectors = vectors();
    let origins = (
        s(&vectors["constants"], "ant_api_url"),
        s(&vectors["constants"], "gateway_url"),
    );
    let mut deviations = 0;
    for entry in arr(&vectors, "exchanges") {
        let Plan::Fetch(fetch) = plan_for(entry) else {
            panic!("{}: not a fetch", id(entry));
        };
        let upstream = &entry["upstream"];
        let chunks: Option<Vec<Vec<u8>>> = upstream["chunks"]
            .as_array()
            .map(|c| c.iter().map(chunk_bytes).collect());
        let head = ResponseHead {
            status: upstream["status"].as_u64().unwrap() as u16,
            headers: fc_dweb::Headers::from_pairs(pairs(&upstream["headers"])),
        };
        let origin = if fetch.node == Node::Ant {
            origins.0
        } else {
            origins.1
        };
        let request_url = format!("{origin}{}", fetch.path);
        let js = &entry["js"];
        assert!(s(js, "request_url").starts_with(origin), "{}", id(entry));
        let backend = backend(&entry["request"]);
        let mut responded = respond(&fetch, backend, head, &request_url, chunks.is_some());
        let mut reads = 0;
        if let Some(declared) = responded.small_text {
            let (decision, taken) = sniff(declared, chunks.as_deref().unwrap());
            reads = taken;
            if decision == SmallTextDecision::Relabel {
                relabel(&mut responded.head);
            }
        }
        let response = &js["response"];
        assert_eq!(
            u64::from(responded.head.status),
            response["status"].as_u64().unwrap(),
            "{}",
            id(entry)
        );
        let mut expected = pairs(&response["headers"]);
        if entry["deviation"].as_str() == Some("native-page-state") {
            // Today's native node answers pass unstripped; the design strips them.
            let before = expected.len();
            expected.retain(|(n, _)| !fc_dweb::PAGE_STATE_RESPONSE_HEADERS.contains(&n.as_str()));
            assert_ne!(expected.len(), before, "{}: nothing to strip", id(entry));
            deviations += 1;
        }
        assert_eq!(responded.head.headers.entries(), expected, "{}", id(entry));
        let body = match response["body"].as_str() {
            Some("intact") => true,
            None => false,
            other => panic!("{}: body {other:?}", id(entry)),
        };
        assert_eq!(responded.body, body, "{}", id(entry));
        // Null where the reference reads ahead for its own reasons (the
        // external gateway's counting stream).
        if let Some(expected) = js["reads_before_response"].as_u64() {
            assert_eq!(reads as u64, expected, "{}", id(entry));
        } else {
            assert_eq!(backend, GATEWAY, "{}", id(entry));
        }
    }
    assert_eq!(deviations, 2);
}

#[test]
fn locations() {
    let vectors = vectors();
    let section = &vectors["locations"];
    for entry in arr(section, "locations") {
        assert_eq!(
            rewrite_gateway_location(s(entry, "location"), s(entry, "request_url")).as_deref(),
            entry["rewritten"].as_str(),
            "{entry}"
        );
    }
    for entry in arr(section, "segments") {
        assert_eq!(
            decode_uri_component(s(entry, "segment")).as_deref(),
            entry["decoded"].as_str(),
            "{entry}"
        );
    }
    for entry in arr(section, "same_segment") {
        assert_eq!(
            same_segment(s(entry, "a"), s(entry, "b")),
            entry["same"].as_bool().unwrap(),
            "{entry}"
        );
    }
}

#[test]
fn operations() {
    let vectors = vectors();
    let ops = &vectors["operations"];
    let head = |entry: &Json| ResponseHead {
        status: entry["status"].as_u64().unwrap_or(200) as u16,
        headers: fc_dweb::Headers::from_pairs(pairs(&entry["headers"])),
    };
    for entry in arr(ops, "strip_page_state") {
        let mut h = head(entry);
        let removed = strip_page_state(&mut h);
        assert_eq!(
            h.headers.entries(),
            pairs(&entry["js"]["headers"]),
            "{entry}"
        );
        assert_eq!(
            removed,
            entry["js"]["rewrapped"].as_bool().unwrap(),
            "{entry}"
        );
    }
    for entry in arr(ops, "strip_decoded_encoding") {
        // proxiedResponseHeaders: the decoded encoding, then page state.
        let mut h = head(entry);
        strip_decoded_encoding(&mut h);
        strip_page_state(&mut h);
        assert_eq!(
            h.headers.entries(),
            pairs(&entry["js"]["headers"]),
            "{entry}"
        );
    }
    for entry in arr(ops, "canonicalize_redirect") {
        let url = s(entry, "request_url");
        let mut ant = head(entry);
        let action = canonicalize_redirect(&mut ant, url, Node::Ant);
        let js = &entry["js"];
        assert_eq!(
            ant.headers.entries(),
            pairs(&js["ant"]["headers"]),
            "{entry}"
        );
        let dropped = js["ant"]["body"].as_str() == Some("dropped");
        assert_eq!(action == BodyAction::Drop, dropped, "{entry}");
        if !js["gateway_redirect_headers"].is_null() {
            let mut gateway = head(entry);
            strip_decoded_encoding(&mut gateway);
            strip_page_state(&mut gateway);
            assert_eq!(
                canonicalize_redirect(&mut gateway, url, Node::Ipfs),
                BodyAction::Keep
            );
            assert_eq!(
                gateway.headers.entries(),
                pairs(&js["gateway_redirect_headers"]),
                "{entry}"
            );
        }
    }
}

#[test]
fn failures() {
    let vectors = vectors();
    for entry in arr(&vectors, "failures") {
        let f = &entry["failure"];
        let thrown = failure::Thrown {
            name: f["name"].as_str().unwrap_or("Error"),
            message: s(f, "message"),
            code: f["code"].as_str(),
            cause_code: f["cause_code"].as_str(),
        };
        for (key, backend) in [("ant", BUNDLED), ("native", NATIVE), ("gateway", GATEWAY)] {
            let error = failure::after_dial(backend, &thrown);
            let js = &entry["js"][key];
            assert_eq!(
                js["status"].as_u64(),
                Some(u64::from(error.status)),
                "{key} {entry}"
            );
            assert_eq!(error.body(), s(js, "body"), "{key} {entry}");
        }
    }
}

#[test]
fn html() {
    use fc_dweb::{HtmlError, decode_html, decode_html_value};

    fn expand_recipe(recipe: &[Json]) -> String {
        let mut out = String::from("0x");
        for part in recipe {
            match part["hex"].as_str() {
                Some(hex) => out.push_str(hex),
                None => out
                    .push_str(&s(part, "repeat").repeat(part["count"].as_u64().unwrap() as usize)),
            }
        }
        out
    }

    let vectors = vectors();
    let c = &vectors["constants"]["html"];
    assert_eq!(
        c["max_html_bytes"].as_u64(),
        Some(fc_dweb::MAX_HTML_BYTES as u64)
    );
    assert_eq!(s(c, "selector"), fc_dweb::HTML_SELECTOR);
    let mut successes = 0;
    for entry in arr(&vectors, "html") {
        let result = if let Some(recipe) = entry["recipe"].as_array() {
            decode_html(&expand_recipe(recipe))
        } else if let Some(text) = entry["result"].as_str() {
            decode_html(text)
        } else {
            decode_html_value(&js_value(&entry["result_json"]))
        };
        let js = &entry["js"];
        let status = js["status"].as_u64().unwrap();
        match result {
            Ok(document) => {
                assert_eq!(status, 200, "{}", id(entry));
                let ok = &js["ok"];
                assert_eq!(
                    format!("0x{}", hex::encode(document.hash)),
                    s(ok, "hash"),
                    "{}",
                    id(entry)
                );
                assert_eq!(
                    document.html.len() as u64,
                    ok["length"].as_u64().unwrap(),
                    "{}",
                    id(entry)
                );
                if let Some(html) = ok["html"].as_str() {
                    assert_eq!(document.html, html, "{}", id(entry));
                }
                successes += 1;
            }
            Err(error) => {
                assert_eq!(u64::from(error.status()), status, "{}", id(entry));
                assert_eq!(error.as_str(), s(js, "error"), "{}", id(entry));
            }
        }
    }
    assert!(successes > 10);
    assert_eq!(HtmlError::TooLarge.status(), 413);
}

#[test]
fn html_class() {
    use fc_dweb::{Class, classify};

    let vectors = vectors();
    for entry in arr(&vectors, "html_class") {
        let class = classify(&js_value(&entry["chain_result"]));
        let expected = match s(&entry["js"], "class") {
            "trusted" => Class::Trusted,
            "conflict" => Class::Conflict,
            "untrusted" => Class::Untrusted,
            other => panic!("{other}"),
        };
        assert_eq!(class, expected, "{}", id(entry));
    }
}

#[test]
fn validation() {
    use std::collections::HashMap;

    use fc_dweb::{PlanRequest, validate_plan};

    /// `{ "$repeat": [text, count] }` stands for the text repeated.
    fn expand(value: &Json) -> Json {
        match value {
            Json::Object(map) if map.contains_key("$repeat") => {
                let spec = map["$repeat"].as_array().unwrap();
                Json::String(
                    spec[0]
                        .as_str()
                        .unwrap()
                        .repeat(spec[1].as_u64().unwrap() as usize),
                )
            }
            Json::Object(map) => {
                Json::Object(map.iter().map(|(k, v)| (k.clone(), expand(v))).collect())
            }
            Json::Array(items) => Json::Array(items.iter().map(expand).collect()),
            other => other.clone(),
        }
    }

    let vectors = vectors();
    assert_eq!(
        vectors["constants"]["design"]["max_message_units"].as_u64(),
        Some(fc_dweb::MAX_MESSAGE_UNITS as u64)
    );
    let requests: HashMap<&str, &Json> = arr(&vectors, "requests")
        .iter()
        .map(|e| (id(e), e))
        .collect();
    let mut refused = HashMap::new();
    for entry in arr(&vectors, "validation") {
        assert_eq!(s(entry, "source"), "design");
        let (request, plan) = match entry["request_id"].as_str() {
            Some(rid) => (&requests[rid]["request"], requests[rid]["plan"].clone()),
            None => (&entry["request"], expand(&entry["plan"])),
        };
        let outcome = validate_plan(
            &js_value(&plan),
            &PlanRequest {
                url: s(request, "url"),
                method: s(request, "method"),
                backend: backend(request),
            },
        );
        let got = match outcome {
            Ok(()) => "valid",
            Err(refusal) => refusal.as_str(),
        };
        assert_eq!(got, s(entry, "expect"), "{}", id(entry));
        // A request whose plan is refused is a deviation from today's dial.
        if let Some(rid) = entry["request_id"].as_str() {
            let expected = match got {
                "valid" => None,
                "path" => Some("plan-paths"),
                other => panic!("{rid}: a request plan refused for {other}"),
            };
            assert_eq!(requests[rid]["deviation"].as_str(), expected, "{rid}");
        }
        *refused.entry(got).or_insert(0) += 1;
    }
    // Every reason is exercised.
    for reason in [
        "valid", "shape", "method", "node", "path", "header", "retry", "timers", "response",
        "trust", "redirect", "error",
    ] {
        assert!(refused.contains_key(reason), "no vector for {reason}");
    }
}
