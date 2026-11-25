//! `swarm.request` through the core (design 0015, SWM-4 PR 5): the real
//! binary, one core playing every case (D11), and the test as main
//! answering the swarm thread's requests from the case
//! ([`swarm_world`]).
//!
//! **What is played:** every `methods` case of `vectors/swarm.json` whose
//! steps are whole calls the swarm thread serves: `requestAccess`,
//! `getCapabilities`, `readChunk`, `readSingleOwnerChunk`,
//! `getUploadStatus`, `getMessagingIdentity`, `subscribe` (D16's open and
//! close inside the request, a GSOC topic's signer mined on the lane),
//! `sendPss` and `sendGsoc` (its signer mined on the lane, PR 8), and the
//! method dispatch's own cases. A `getUploadStatus` case's `publishFiles`
//! steps aren't played (the stores and parts come with PRs 6 and 7): the
//! tag each gave the site is set in the thread's world instead, as the
//! reference's upload recorded it. Not played, and counted: cases with
//! other methods (PRs 6 to 9).
//!
//! **What is checked,** each step: the answer, read back from its typed
//! form, against the reference's (the case's `core` where a deviation
//! changes it); the core's node calls against the grammar's honest
//! scenario and its row's forms and counts; the subscriptions main opened
//! and closed; and that the thread holds no charge and no request once the
//! step has ended.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod swarm_world;

use std::time::Duration;

use fc_json::index::{Index, Kind};
use serde_json::json;
use swarm_world::logic::{self, Want};
use swarm_world::{Main, Name, Naming, Script, grants_json, named_page, page, wire_typed};

/// The methods whose cases this step plays.
const PLAYED: [&str; 9] = [
    "swarm_requestAccess",
    "swarm_getCapabilities",
    "swarm_readChunk",
    "swarm_readSingleOwnerChunk",
    "swarm_getUploadStatus",
    "swarm_getMessagingIdentity",
    "swarm_subscribe",
    "swarm_sendPss",
    "swarm_sendGsoc",
];

/// Cases of those methods not played, each with why.
const LEFT_OUT: &[(&str, &str)] = &[
    (
        "subscribe-no-page",
        "executeSwarmMethod with no page: a swarm.request is always a page's (0011)",
    ),
    (
        "send-pss-targets-megabyte",
        "a 1 MiB targets string: a request is one frame (0005), and 0011's walk bounds a \
         page request's size before main sends it",
    ),
];

fn row_of(method: &str) -> &'static str {
    match method {
        "swarm_requestAccess" => "requestAccess",
        "swarm_getCapabilities" => "getCapabilities",
        "swarm_readChunk" => "readChunk",
        "swarm_readSingleOwnerChunk" => "readSingleOwnerChunk",
        "swarm_getUploadStatus" => "getUploadStatus",
        "swarm_getMessagingIdentity" => "getMessagingIdentity",
        "swarm_subscribe" => "subscribe",
        "swarm_sendPss" => "sendPss",
        "swarm_sendGsoc" => "sendGsoc",
        other => panic!("{other}"),
    }
}

/// How main approved a send: a standing rule read custody and showed no
/// prompt; anything else the user's. Other methods carry none.
fn approval_of(method: &str, step: fc_json::index::Value<'_, '_>) -> Option<&'static str> {
    if method != "swarm_sendPss" && method != "swarm_sendGsoc" {
        return None;
    }
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    let prompted = events.iter().any(|e| e.get("prompt").is_some());
    let ruled = events
        .iter()
        .any(|e| e.get("custody").is_some_and(|c| c.kind() == Kind::False));
    Some(if ruled && !prompted { "auto" } else { "user" })
}

#[test]
fn whole_calls_play_every_case() {
    let text = logic::text_of("swarm.json");
    let index = Index::new(&text).unwrap();
    let grammar_text = logic::text_of("swarm-grammar.json");
    let grammar_index = Index::new(&grammar_text).unwrap();
    let grammar = grammar_index.root();
    let keys_text = logic::text_of("keys.json");
    let keys_index = Index::new(&keys_text).unwrap();
    let keys = logic::keys(&keys_index);
    let scenarios = logic::scenarios(grammar);

    let mut main = swarm_world::main();
    let (mut played, mut main_answered, mut seeded) = (0usize, 0usize, 0usize);
    let mut later = 0usize;
    let mut scenarios_used = std::collections::BTreeSet::new();
    let mut skipped = std::collections::BTreeSet::new();
    let mut left_out_seen = Vec::new();
    for case in logic::get(index.root(), "methods").children() {
        let id = logic::string(logic::get(case, "id"));
        let steps: Vec<_> = logic::get(case, "steps").children().collect();
        let methods: Vec<Option<String>> = steps
            .iter()
            .map(|s| s.get("method").map(logic::string))
            .collect();
        let dispatch = steps
            .iter()
            .all(|s| s.get("page").is_some_and(|p| p.kind() == Kind::False))
            && methods
                .iter()
                .all(|m| m.as_ref().is_none_or(|m| !PLAYED.contains(&m.as_str())))
            && id.starts_with("method-");
        let ours = methods
            .iter()
            .any(|m| m.as_ref().is_some_and(|m| PLAYED.contains(&m.as_str())));
        if !ours && !dispatch {
            continue;
        }
        if let Some((_, why)) = LEFT_OUT.iter().find(|(l, _)| *l == id) {
            assert!(!why.is_empty());
            skipped.insert(id.clone());
            left_out_seen.push(id);
            continue;
        }
        let status = methods
            .iter()
            .any(|m| m.as_deref() == Some("swarm_getUploadStatus"));
        let others = methods.iter().any(|m| {
            m.as_ref().is_some_and(|m| {
                !PLAYED.contains(&m.as_str())
                    && m != "swarm_unsubscribe"
                    && !(status && m == "swarm_publishFiles")
            })
        });
        if others && !dispatch {
            later += 1;
            skipped.insert(id);
            continue;
        }
        let deviation = case.get("deviation").map(logic::string);
        let want = match &deviation {
            Some(d) => logic::shared_answer(d, logic::get(case, "core"))
                .unwrap_or_else(|| panic!("{id}: a deviation this step doesn't answer: {d}")),
            None => Want::Reference,
        };
        let origin = logic::js(logic::get(case, "origin"));
        let subscribe_check = case.get("session").map(|s| {
            let check = logic::get(s, "subscribe_check");
            if logic::get(check, "ok").kind() == Kind::True {
                Ok(())
            } else {
                Err(logic::js(logic::get(check, "reason")))
            }
        });
        let mut script = Script {
            world: logic::TestWorld::of(case),
            node: logic::Node::of(case, &keys),
            readiness: logic::publish_readiness(case),
            subscribe_check,
            key: origin.clone(),
            naming: None,
        };
        main.world(json!({
            "reset": true,
            "clock": script.world.now,
            "grants": grants_json(&script.world),
        }));
        for (k, step) in steps.iter().enumerate() {
            let sid = if steps.len() > 1 {
                format!("{id}/{k}")
            } else {
                id.clone()
            };
            if let Some(clock) = step.get("clock") {
                script.world.now = logic::number(clock) as u64;
                main.world(json!({ "clock": script.world.now }));
            }
            if methods[k].as_deref() == Some("swarm_unsubscribe") {
                // Main's own: it ends the subscription it opened.
                continue;
            }
            let Some(handoff) = logic::handoff(*step, &origin, &mut script.world) else {
                assert_eq!(
                    step.get("requests").map_or(0, |r| r.children().count()),
                    0,
                    "{sid}"
                );
                main_answered += 1;
                continue;
            };
            if handoff.name.as_deref() == Some("swarm_publishFiles") {
                // The tag the reference's upload gave the site.
                if let Some(tag) = step
                    .get("result")
                    .and_then(|r| r.get("tagUid"))
                    .filter(|t| t.kind() == Kind::Number)
                {
                    main.world(json!({
                        "grants": grants_json(&script.world),
                        "tags": [[logic::number(tag) as u64, handoff.key.as_str()]],
                    }));
                }
                seeded += 1;
                continue;
            }
            if let Some(change) = case.get("at_execute") {
                script.world.change(&handoff.key, change);
            }
            main.world(json!({ "grants": grants_json(&script.world) }));
            script.key = handoff.key.clone();
            let method = match step.get("method") {
                Some(m) => format!(r#"{{"string":{}}}"#, m.raw()),
                None => wire_typed(logic::get(*step, "method_typed")),
            };
            let params = if handoff.name.as_deref() == Some("swarm_requestAccess") {
                r#"{"object":[]}"#.to_owned()
            } else {
                wire_typed(logic::get(*step, "params"))
            };
            assert!(!swarm_world::has_part(logic::get(*step, "params")), "{sid}");
            let approval = handoff
                .name
                .as_deref()
                .and_then(|name| approval_of(name, *step))
                .map_or(String::new(), |a| format!(r#","approval":"{a}""#));
            let request = format!(r#"{{"method":{method},"params":{params}{approval}}}"#);
            let page = page(handoff.key.as_str());
            let ran = main.play(&mut script, &page, &request);
            played += 1;

            let last = k + 1 == steps.len();
            logic::check_outcome(&sid, want, last, case, *step, &ran.outcome);
            // At the page's timer the core cancels its open call, unless
            // main's answer to it was read first (the event loop takes it
            // as main's cancel reaches the swarm thread): either way the
            // answer is taken and dropped, and nothing is held after.
            let Some(name) = handoff.name.filter(|m| PLAYED.contains(&m.as_str())) else {
                assert!(ran.calls.is_empty() && ran.ready.is_empty(), "{sid}");
                continue;
            };
            // A subscription the page got is the one main opened; one that
            // didn't reach it is closed.
            if name == "swarm_subscribe"
                && matches!(ran.outcome, fc_swarm_provider::machine::Outcome::Result(_))
            {
                assert_eq!(ran.opened.len(), 1, "{sid}: one subscription opened");
                assert!(ran.closed.is_empty(), "{sid}: and kept");
                let result = logic::get(*step, "result");
                assert!(logic::get(result, "kind").is_str(ran.opened[0].kind.as_str()));
                assert!(logic::get(result, "key").is_str(&logic::hex(&ran.opened[0].key)));
            } else {
                assert_eq!(ran.closed.len(), ran.opened.len(), "{sid}: closed");
            }
            let row = row_of(&name);
            let shape = ran.ran();
            logic::check_row_shape(&sid, grammar, row, &shape);
            match scenarios.get(&sid) {
                Some(scenario) => {
                    assert!(logic::get(*scenario, "row").is_str(row), "{sid}");
                    let earlier = last && want == Want::Exact;
                    if !earlier {
                        logic::check_scenario(&sid, *scenario, &shape, false);
                    }
                    scenarios_used.insert(sid.clone());
                }
                None => assert!(
                    ran.calls.is_empty() || want == Want::Transport,
                    "{sid}: calls, and no honest scenario"
                ),
            }
        }
    }
    assert_eq!(
        left_out_seen.len(),
        LEFT_OUT.len(),
        "every case left out exists"
    );
    // Every honest scenario of the rows played, but a skipped case's.
    for (sid, scenario) in &scenarios {
        let from = logic::string(logic::get(*scenario, "from"));
        let Some(case_id) = from.strip_prefix("methods/") else {
            continue;
        };
        let row = logic::string(logic::get(*scenario, "row"));
        if skipped.contains(case_id) || !PLAYED.iter().any(|m| row_of(m) == row) {
            continue;
        }
        assert!(
            scenarios_used.contains(sid),
            "{sid}: an honest scenario no step played"
        );
    }
    assert_eq!(
        (played, main_answered, seeded, later),
        (193, 16, 7, 2),
        "steps played, main's own, uploads seeded and later cases"
    );
    assert_eq!(scenarios_used.len(), 89);
}

/// A `readChunk` of the vectors' 11-byte chunk.
const READ_CHUNK: &str = r#"{"method":{"string":"swarm_readChunk"},"params":{"object":[["reference",{"string":"f9335c1f06d729ae3e725352a445fa01a1e9dc20e937f0ef19ab199b1fb2827b"}]]}}"#;
const SITE: &str = "https://app.example";

fn connected(main: &mut Main) {
    main.world(json!({
        "reset": true,
        "clock": 1_767_225_600_123u64,
        "grants": { SITE: {
            "origin": SITE, "connectedAt": 1, "lastUsed": 1,
            "autoApprove": { "publish": false, "feeds": false, "signing": false, "messaging": false },
        } },
    }));
}

/// The next request the core makes of main.
fn asked(main: &mut Main, method: &str) -> serde_json::Value {
    let message = main.core.recv();
    assert_eq!(message["type"], "request", "expected {method}: {message}");
    assert_eq!(message["method"], method, "{message}");
    message
}

#[test]
fn the_door_answers_before_any_machine_runs() {
    // The Swarm grants haven't moved: not_moved, nothing asked.
    let mut main = swarm_world::main_with(&[], &[]);
    let id = main.request(&page(SITE), READ_CHUNK);
    let answer = main.core.response(id);
    assert_eq!(answer["error"]["code"], "not_moved", "{answer}");
    assert_eq!(answer["error"]["data"], json!({ "store": "swarm" }));

    let mut main = swarm_world::main();
    connected(&mut main);
    // A store method before the stores move (D3); main's own unsubscribe
    // (D5); a streamed read not yet served; params that aren't typed.
    for (request, code) in [
        (
            r#"{"method":{"string":"swarm_listFeeds"},"params":{"undefined":true}}"#,
            "not_moved",
        ),
        (
            r#"{"method":{"string":"swarm_unsubscribe"},"params":{"undefined":true}}"#,
            "invalid_argument",
        ),
        (
            r#"{"method":{"string":"swarm_readData"},"params":{"undefined":true}}"#,
            "internal",
        ),
        (
            r#"{"method":"swarm_readChunk","params":{"undefined":true}}"#,
            "invalid_argument",
        ),
    ] {
        let id = main.request(&page(SITE), request);
        let answer = main.core.response(id);
        assert_eq!(answer["error"]["code"], code, "{request}: {answer}");
    }
    // Only a page may call it.
    let id = main.id();
    let answer = main.core.call(
        id,
        "swarm.request",
        serde_json::from_str(READ_CHUNK).unwrap(),
    );
    assert_eq!(answer["error"]["code"], "forbidden", "{answer}");
    settled(&mut main);
}

/// The thread holds nothing, once the writer has told it of the answers
/// it wrote.
fn settled(main: &mut Main) {
    for _ in 0..200 {
        if main.world(json!({})) == json!({ "memory": 0, "requests": 0 }) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("the thread still holds {}", main.world(json!({})));
}

#[test]
fn admission_busy_and_the_deadline_through_the_pipe() {
    let mut main = swarm_world::main_with(
        &["swarm"],
        &[
            ("FREEDOM_CORED_TEST_SWARM_RUNNING", "1"),
            ("FREEDOM_CORED_TEST_SWARM_WAITING", "0"),
        ],
    );
    connected(&mut main);
    // The first runs, to its readiness check, under a 300 ms deadline.
    let first = main.request(
        &page(SITE),
        &READ_CHUNK.replace(r#""params""#, r#""deadline_ms":300,"params""#),
    );
    let ready = asked(&mut main, "shell.swarm_ready");
    assert_eq!(
        ready["params"],
        json!({ "for": first, "check": "reachable" })
    );
    // The second finds no place and no room to wait: 4900 busy, typed.
    let second = main.request(&page(SITE), READ_CHUNK);
    let answer = main.core.response(second);
    assert_eq!(
        answer["result"],
        json!({ "error_typed": { "object": [
            ["code", { "number": "4900" }],
            ["message", { "string": "busy" }],
            ["data", { "object": [["reason", { "string": "busy" }]] }],
        ] } })
    );
    // At its deadline the first is cancelled, and so is its check: the
    // cancel goes first.
    let cancel = main.core.recv();
    assert_eq!(cancel, json!({ "type": "cancel", "id": ready["id"] }));
    let answer = main.core.response(first);
    assert_eq!(answer["error"]["code"], "cancelled", "{answer}");
    // The check keeps its slot until main's answer; then nothing is held.
    assert_eq!(main.world(json!({}))["requests"], 1);
    main.refuse(
        ready["id"].as_u64().unwrap(),
        json!({ "code": "cancelled", "message": "Cancelled" }),
    );
    settled(&mut main);
}

#[test]
fn a_malformed_answer_ends_the_core() {
    for (what, answer) in [
        (
            "a readiness of another shape",
            json!({ "result": { "ok": "yes" } }),
        ),
        (
            "a refusal of a check never cancelled",
            json!({ "error": { "code": "cancelled", "message": "Cancelled" } }),
        ),
        (
            "a whole call with no body",
            json!({ "call": { "result": { "status": 200, "status_text": "OK", "headers": [] } } }),
        ),
        (
            "base64 that doesn't decode",
            json!({ "call": { "result": { "status": 200, "status_text": "OK", "headers": [], "body_base64": "AQ" } } }),
        ),
        (
            "a chunk past its cap",
            json!({ "call": { "result": { "status": 200, "status_text": "OK", "headers": [],
                "body_base64": base64_of(&[0u8; 4202]) } } }),
        ),
    ] {
        let mut main = swarm_world::main();
        connected(&mut main);
        main.request(&page(SITE), READ_CHUNK);
        let ready = asked(&mut main, "shell.swarm_ready");
        let id = ready["id"].as_u64().unwrap();
        let reply = match answer.get("call") {
            Some(call) => {
                main.answer(id, json!({ "ok": true }));
                let call_id = asked(&mut main, "shell.swarm_api")["id"].as_u64().unwrap();
                json!({ "type": "response", "id": call_id })
                    .as_object()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .chain(call.as_object().unwrap().clone())
                    .collect::<serde_json::Map<_, _>>()
            }
            None => json!({ "type": "response", "id": id })
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .chain(answer.as_object().unwrap().clone())
                .collect(),
        };
        main.core.send(&serde_json::Value::Object(reply));
        assert_eq!(main.core.exit_code(Duration::from_secs(10)), 76, "{what}");
    }
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A name-keyed document's page request, `eip1193.request` `eth_accounts`,
/// answered while main serves naming's lookups: its answer.
fn accounts(main: &mut Main, naming: &mut Naming, navigation: u64) -> serde_json::Value {
    let id = main.id();
    let world: serde_json::Value = serde_json::from_str(ACCOUNTS_WORLD).unwrap();
    main.core.send(&json!({
        "type": "request", "id": id, "method": "eip1193.request",
        "params": { "method": "eth_accounts", "params": [], "world": world },
        "context": { "caller": "page", "page": named_page(navigation) },
    }));
    loop {
        let message = main.core.recv();
        match (message["type"].as_str(), message["method"].as_str()) {
            (Some("request"), Some("shell.rpc")) => main.serve_rpc(naming, &message),
            (Some("request"), Some("shell.prefetch")) | (Some("cancel"), _) => {}
            // The page's answer: `{ result }` or `{ error }`.
            (Some("response"), _) if message["id"] == id => {
                return message["result"]["result"].clone();
            }
            _ => panic!("{message}"),
        }
    }
}

/// eip1193.json's `name-accounts-honest` world: the Identity & Wallet
/// switch on, the abandon wallet first.
const ACCOUNTS_WORLD: &str = r#"{"enabled":true,"chain":null,"window_chain":null,"wallets":[{"index":0,"name":"Main Wallet","address":"0x9858EfFD232B4033E47d90003D41EC34EcaEda94","type":"mnemonic"}],"networks":{"1":{"name":"Ethereum","available":true},"100":{"name":"Gnosis","available":true}},"active":0}"#;

/// `getUploadStatus` of a tag the site doesn't own: refused once the live
/// facts are read, `tag_ownership_mismatch` while the name holds and the
/// document is live, `NO_ADDRESS` once the name doesn't serve its key.
const UNOWNED_STATUS: &str = r#"{"method":{"string":"swarm_getUploadStatus"},"params":{"object":[["tagUid",{"number":"7"}]]}}"#;

fn reason(outcome: &fc_swarm_provider::machine::Outcome) -> String {
    let fc_swarm_provider::machine::Outcome::Error(failure) = outcome else {
        panic!("{outcome:?}")
    };
    failure
        .data
        .as_ref()
        .unwrap()
        .get("reason")
        .as_js_string()
        .unwrap()
        .as_str()
        .to_owned()
}

/// A name-keyed document (D1, through the pipe): the swarm thread checks
/// the name with the core's own naming before main's recheck; a check that
/// fails ends the document's binding for good, for every later check of
/// either family: a later Swarm check resolves nothing, an EIP-1193
/// failure refuses a Swarm check, and a Swarm failure an EIP-1193 one. A
/// new document binds again.
#[test]
fn a_failed_name_ends_the_binding_for_swarm_and_ethereum() {
    let mut main = swarm_world::main_with(
        &["swarm"],
        &[("FREEDOM_CORED_TEST_EIP1193_NAMES_UNCACHED", "1")],
    );
    main.configure_naming();
    // The dApp grant main still writes: a holding name reveals the account.
    let dapp = json!({ swarm_world::NAME: {
        "origin": swarm_world::NAME, "connectedAt": 1, "lastUsed": 1, "walletIndex": 0,
        "chainId": 100, "autoApprove": { "signing": false, "transactions": [] },
    } });
    std::fs::write(
        main.core.grant_root.join("dapp-permissions.json"),
        dapp.to_string(),
    )
    .unwrap();
    main.world(json!({
        "reset": true,
        "clock": 1_767_225_600_123u64,
        "grants": { swarm_world::NAME: {
            "origin": swarm_world::NAME, "connectedAt": 1, "lastUsed": 1,
            "autoApprove": { "publish": false, "feeds": false, "signing": false, "messaging": false },
        } },
    }));
    let mut script = Script {
        world: logic::TestWorld::new(1_767_225_600_123),
        node: logic::Node::new(),
        readiness: Ok(()),
        subscribe_check: None,
        key: fc_json::JsString::from(swarm_world::NAME),
        naming: Some(Naming::new()),
    };
    let names = |script: &mut Script, names: &[Name]| {
        script.naming.as_mut().unwrap().names.extend(names);
    };
    let checks = |script: &Script| script.naming.as_ref().unwrap().checks;

    // The name holds: main's recheck, then the method's own refusal.
    names(&mut script, &[Name::Serves]);
    let ran = main.play(&mut script, &named_page(1), UNOWNED_STATUS);
    assert_eq!((checks(&script), ran.rechecks), (1, 1));
    assert_eq!(reason(&ran.outcome), "tag_ownership_mismatch");

    // It fails: NO_ADDRESS, no recheck; and the document's next request
    // resolves nothing, whatever the name would answer now.
    names(&mut script, &[Name::Fails]);
    let ran = main.play(&mut script, &named_page(1), UNOWNED_STATUS);
    assert_eq!((checks(&script), ran.rechecks), (2, 0));
    assert_eq!(reason(&ran.outcome), "no_address");
    let ran = main.play(&mut script, &named_page(1), UNOWNED_STATUS);
    assert_eq!((checks(&script), ran.rechecks), (2, 0));
    assert_eq!(reason(&ran.outcome), "no_address");
    // ...and the document's EIP-1193 checks read it too: no account, and
    // nothing resolved.
    let mut naming = script.naming.take().unwrap();
    assert_eq!(accounts(&mut main, &mut naming, 1), json!([]));
    assert_eq!(naming.checks, 2);

    // An EIP-1193 check that finds the name moved ends a new document's
    // binding: its Swarm check resolves nothing.
    naming.names.extend([Name::Moved]);
    assert_eq!(accounts(&mut main, &mut naming, 2), json!([]));
    assert_eq!(naming.checks, 3);
    script.naming = Some(naming);
    let ran = main.play(&mut script, &named_page(2), UNOWNED_STATUS);
    assert_eq!((checks(&script), ran.rechecks), (3, 0));
    assert_eq!(reason(&ran.outcome), "no_address");

    // A document whose name holds reveals the account through both of its
    // EIP-1193 checks, and binds on.
    let mut naming = script.naming.take().unwrap();
    naming.names.extend([Name::Serves, Name::Serves]);
    assert_eq!(
        accounts(&mut main, &mut naming, 3),
        json!(["0x9858EfFD232B4033E47d90003D41EC34EcaEda94"])
    );
    assert_eq!(naming.checks, 5);
    script.naming = Some(naming);
}
