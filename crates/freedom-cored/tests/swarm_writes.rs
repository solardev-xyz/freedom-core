//! The Swarm stores, the vault's asks and SW-1's hold through the core
//! (design 0015, SWM-4 PR 7): the real binary, its stores moved
//! (`swarm_stores`, D3) and its vault the test mnemonic's, one core playing
//! every case of a group (D11), and the test as main answering the swarm
//! thread's requests from the case ([`swarm_world`]).
//!
//! **What is played:** every `methods` case of the Publish methods
//! (`publishData`, `publishFiles`, `publishChunk`, and `getUploadStatus`
//! with the uploads before it) and of the Feeds and SOC methods
//! (`createFeed`, `updateFeed`, `writeFeedEntry`, `writeSingleOwnerChunk`,
//! `getSigningIdentity`), but `write-soc-no-page`, which no
//! `swarm.request` reaches. Main's writes before a step's hand-over (a feed
//! prompt's pick of identity and the feed grant, an unlock) are made as
//! `swarm.identities` will make them, through the core's keeper
//! (`test.swarm_feed_change`); a case's `at_execute` locks the vault, or
//! revokes the feed grant or the connection, before the request.
//!
//! **What is checked,** each step: the answer (the case's `core` where a
//! deviation changes it); the calls against the row's ready check, forms
//! and counts, and against the grammar's honest scenario exactly (query,
//! headers and bodies, a SOC's signature among them, which is the core's
//! vault's: the vectors' own); the signatures the vault made (its marker
//! counts them) against the step's `sign_soc` events. Each case:
//! `swarm-feeds.json`'s text as the core left it on disk, and the
//! history's rows read back from `publish-history.sqlite` with rusqlite.
//!
//! Then the stores' own paths through the core: `not_moved` before the
//! move with nothing written; a failure at each write step; a full feed
//! store; a restart sweeping a row left `uploading`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod swarm_world;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fc_json::JsValue;
use fc_json::index::{Index, KeyOrder, Kind, Value as V};
use fc_swarm_provider::machine::Body;
use fc_swarm_provider::stores::history::{self, Cell};
use serde_json::json;
use swarm_world::logic::write_node::WriteNode;
use swarm_world::logic::{self, Want, get, number, string};
use swarm_world::{Main, Script, grants_json, page, wire_typed};

const PUBLISH: [&str; 4] = [
    "swarm_publishData",
    "swarm_publishFiles",
    "swarm_publishChunk",
    "swarm_getUploadStatus",
];

const FEEDS: [&str; 5] = [
    "swarm_createFeed",
    "swarm_updateFeed",
    "swarm_writeFeedEntry",
    "swarm_writeSingleOwnerChunk",
    "swarm_getSigningIdentity",
];

/// Cases of the feed and SOC writes not played, each with why (none of the
/// uploads').
const LEFT_OUT: &[(&str, &str)] = &[(
    "write-soc-no-page",
    "executeSwarmMethod with no page: a swarm.request is always a page's (0011)",
)];

/// The row a step's request plays, as swarm-grammar.json names it.
fn row_of(method: &str) -> &'static str {
    match method {
        "swarm_publishData" => "publishData",
        "swarm_publishFiles" => "publishFiles",
        "swarm_publishChunk" => "publishChunk",
        "swarm_getUploadStatus" => "getUploadStatus",
        "swarm_createFeed" => "createFeed",
        "swarm_updateFeed" => "updateFeed",
        "swarm_writeFeedEntry" => "writeFeedEntry",
        "swarm_writeSingleOwnerChunk" => "writeSingleOwnerChunk",
        "swarm_getSigningIdentity" => "getSigningIdentity",
        other => panic!("{other}"),
    }
}

/// The deviations these cases mark whose answer is the reference's (the
/// rest give the core's own `core`, or the page's timer).
fn core_answer(deviation: &str, core: V<'_, '_>) -> Want {
    if let Some(want) = logic::shared_answer(deviation, core) {
        return want;
    }
    let text = string(core);
    match deviation {
        "index-probe" | "feed-wrap-root" => {}
        "stamps-one-read" => assert!(text.starts_with("one GET /stamps; the same"), "{text}"),
        other => panic!("a deviation this test doesn't answer: {other}: {text}"),
    }
    Want::Reference
}

/// The step's parts, from their seeds.
fn parts_of(step: V<'_, '_>) -> BTreeMap<u32, Vec<u8>> {
    let mut out = BTreeMap::new();
    for part in step
        .get("parts")
        .map(|p| p.children())
        .into_iter()
        .flatten()
    {
        let length = number(get(part, "length")) as usize;
        let data = match part.get("seed") {
            Some(seed) => logic::content(&string(seed), length),
            None => {
                let unit = string(get(part, "repeat"));
                unit.repeat(number(get(part, "count")) as usize)
                    .into_bytes()
            }
        };
        assert_eq!(data.len(), length);
        assert_eq!(logic::sha(&data), string(get(part, "sha256")));
        out.insert(number(get(part, "part")) as u32, data);
    }
    out
}

/// How main approved a step: the feed and SOC writes say it in their
/// hand-over (`service.approval`); an upload is `user` after its prompt,
/// `auto` when the site's rule answered; `getUploadStatus` has none.
fn approval_of(method: &str, step: V<'_, '_>) -> Option<&'static str> {
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    if FEEDS.contains(&method) {
        let service = events.iter().find_map(|e| e.get("service"))?;
        return match service.get("approval") {
            Some(a) if a.is_str("user") => Some("user"),
            Some(a) if a.is_str("auto") => Some("auto"),
            _ => None,
        };
    }
    if method == "swarm_getUploadStatus" {
        return None;
    }
    let prompted = events.iter().any(|e| {
        e.get("prompt")
            .is_some_and(|p| get(p, "kind").is_str("swarm.publish"))
    });
    Some(if prompted { "user" } else { "auto" })
}

/// The vault as the core holds it, locked or not.
struct Vault {
    unlocked: bool,
}

impl Vault {
    fn set(&mut self, main: &mut Main, unlocked: bool) {
        if self.unlocked != unlocked {
            main.set_vault(unlocked);
            self.unlocked = unlocked;
        }
    }
}

/// Main's own writes before it hands the step over, as `swarm.identities`
/// will make them (a feed prompt's pick of identity, then the feed grant;
/// an unlock), and the case's `at_execute` as the dispatcher hands the
/// request over.
fn main_writes(
    main: &mut Main,
    vault: &mut Vault,
    script: &mut Script,
    case: V<'_, '_>,
    step: V<'_, '_>,
    key: &str,
    first: bool,
) {
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    for event in &events {
        if event.get("service").is_some() {
            break;
        }
        let Some(prompt) = event.get("prompt") else {
            continue;
        };
        let answer = get(prompt, "answer");
        if answer.get("approve").is_none_or(|a| a.kind() != Kind::True) {
            continue;
        }
        match string(get(prompt, "kind")).as_str() {
            "vault.unlock" => vault.set(main, true),
            "swarm.feed" => {
                let picked = string(get(get(answer, "choices"), "identity"));
                let new_id = string(get(get(get(prompt, "view"), "newIdentity"), "id"));
                let options = json!({ "activate": true, "source": "user" });
                // A new identity at the next index: the one the prompt
                // previewed, which nothing took meanwhile.
                let change = if picked == "bee-wallet" {
                    json!({ "op": "ensureAntWalletIdentity", "key": key, "options": options })
                } else if picked == new_id {
                    json!({ "op": "createAppScopedIdentity", "key": key, "options": options })
                } else {
                    json!({ "op": "activateIdentity", "key": key, "identityId": picked })
                };
                let made = main.feed_change(change);
                assert!(made.get("value").is_some(), "{made}");
                let made = main.feed_change(json!({ "op": "grantFeedAccess", "key": key }));
                assert!(made.get("value").is_some(), "{made}");
            }
            // An upload's prompt writes nothing.
            "swarm.publish" => {}
            other => panic!("a prompt {other}"),
        }
    }
    if first && let Some(changes) = case.get("at_execute") {
        for (what, how) in changes.members() {
            match (string(what).as_str(), string(how).as_str()) {
                ("vault", "locked") => vault.set(main, false),
                ("feed_access", "revoked") => {
                    let made = main.feed_change(json!({ "op": "revokeFeedAccess", "key": key }));
                    assert!(made.get("value").is_some(), "{made}");
                }
                (what, how) => {
                    let key = fc_json::JsString::from(key);
                    script.world.apply(&key, what, how);
                }
            }
        }
    }
    main.world(json!({ "grants": grants_json(&script.world) }));
}

/// The core's calls against the grammar's honest scenario, exactly (a
/// prefix of it where the core's own error ends the request earlier).
fn check_calls(sid: &str, scenario: V<'_, '_>, played: &swarm_world::Played, earlier: bool) {
    let main_headers = ["accept", "accept-encoding"];
    let wants: Vec<_> = get(scenario, "calls").children().collect();
    let paths: Vec<&str> = played.calls.iter().map(|c| c.call.path.as_str()).collect();
    if earlier {
        assert!(played.calls.len() <= wants.len(), "{sid}: {paths:?}");
    } else {
        assert_eq!(wants.len(), played.calls.len(), "{sid}: {paths:?}");
    }
    let pairs = |v: Option<V<'_, '_>>| -> Vec<(String, String)> {
        v.map(|q| {
            q.children()
                .map(|pair| {
                    let mut it = pair.children();
                    (string(it.next().unwrap()), string(it.next().unwrap()))
                })
                .collect()
        })
        .unwrap_or_default()
    };
    for (at, (want, logged)) in wants.iter().zip(&played.calls).enumerate() {
        let call = &logged.call;
        let what = format!("{sid}: call {at} {}", call.path);
        assert!(get(*want, "form").is_str(call.form.as_str()), "{what}");
        assert!(get(*want, "method").is_str(call.method()), "{what}");
        assert!(get(*want, "path").is_str(&call.path), "{what}");
        assert_eq!(pairs(want.get("query")), call.query, "{what}: query");
        let headers: Vec<(String, String)> = pairs(want.get("headers"))
            .into_iter()
            .filter(|(k, _)| !main_headers.contains(&k.as_str()))
            .collect();
        assert_eq!(headers, call.headers, "{what}: headers");
        let body = match &call.body {
            None => None,
            Some(Body::Base64(bytes)) => Some(bytes.clone()),
            Some(Body::Stream { .. }) => Some(played.bodies[&at].clone()),
        };
        match (want.get("body"), body) {
            // The recording leaves out an empty body.
            (None, None) => {}
            (None, Some(got)) if got.is_empty() => {}
            (Some(w), Some(got)) => {
                assert_eq!(number(get(w, "bytes")) as usize, got.len(), "{what}: body");
                match (w.get("base64"), w.get("sha256")) {
                    (Some(b), _) => assert_eq!(logic::b64(&string(b)), got, "{what}: body"),
                    (None, Some(d)) => assert_eq!(logic::sha(&got), string(d), "{what}: body"),
                    _ => panic!("{what}: a body spec"),
                }
            }
            (w, got) => panic!("{what}: body {:?} against {:?}", w.map(|w| w.raw()), got),
        }
        match (want.get("feed"), call.feed) {
            (None, None) => {}
            (Some(f), Some(feed)) => {
                assert!(get(f, "owner").is_str(&logic::hex(&feed.owner)), "{what}");
                assert_eq!(number(get(f, "index")) as u64, feed.index, "{what}");
            }
            _ => panic!("{what}: feed"),
        }
        if let Some(m) = want.get("max_bytes") {
            assert_eq!(number(m) as usize, call.max_bytes, "{what}");
        }
    }
}

/// The history's rows as `getEntries()` answers them, read from the
/// database the core writes.
fn history_of(root: &Path) -> String {
    let path = root.join(history::FILE_NAME);
    let conn = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let mut statement = conn.prepare(history::ALL_SQL).unwrap();
    let columns = statement.column_count();
    let rows: Vec<Vec<Cell>> = statement
        .query_map([], |row| {
            (0..columns)
                .map(|i| {
                    use rusqlite::types::ValueRef;
                    Ok(match row.get_ref(i)? {
                        ValueRef::Null => Cell::Null,
                        ValueRef::Integer(n) => Cell::Integer(n),
                        ValueRef::Real(n) => Cell::Real(n),
                        ValueRef::Text(t) => Cell::Text(String::from_utf8_lossy(t).into_owned()),
                        ValueRef::Blob(b) => Cell::Blob(b.to_vec()),
                    })
                })
                .collect()
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    history::entries(&rows).unwrap().stringify()
}

/// The feed and SOC writes' rows the core leaves (as
/// `feed_writes_vectors.rs` reads them): the reference's, but where a
/// deviation gives the core's own error, the step's row ends `failed` with
/// the core's text and nothing the write gave, or is absent where the core
/// refuses before it (`core_before`).
fn expected_feed_history(case: V<'_, '_>, want: Want) -> String {
    let rows =
        fc_json::parse(&get(get(case, "after"), "history").stringify(KeyOrder::Property)).unwrap();
    let core_error = match want {
        Want::Exact => get(case, "core")
            .get("error")
            .map(|e| string(get(e, "message"))),
        Want::Transport => Some(fc_swarm_provider::machine::node::ERROR_TEXT.to_owned()),
        // The page's timer (`deadlines`): a request that ends without its
        // machine ends its row failed with `cancelled`.
        Want::Cancelled => Some("cancelled".to_owned()),
        Want::Reference => None,
    };
    let Some(message) = core_error else {
        return rows.stringify();
    };
    let mut rows = rows.as_array().unwrap().to_vec();
    if case.get("core_before").is_some() {
        rows.remove(0);
        return JsValue::Array(rows).stringify();
    }
    let row = &mut rows[0];
    row.set("status", JsValue::string("failed"));
    row.set("errorMessage", JsValue::string(message.as_str()));
    for field in ["reference", "bzzUrl", "batchIdUsed"] {
        row.set(field, JsValue::Null);
    }
    let timestamp = row.get("timestamp").cloned().unwrap();
    row.set("completedAt", timestamp);
    JsValue::Array(rows).stringify()
}

/// The uploads' rows the core leaves (as `publish_vectors.rs` reads them):
/// the reference's, but where a deviation turns the result into the core's
/// error, the row ends `failed` with the core's text and nothing the upload
/// gave.
fn expected_publish_history(case: V<'_, '_>, want: Want) -> String {
    let rows =
        fc_json::parse(&get(get(case, "after"), "history").stringify(KeyOrder::Property)).unwrap();
    let message = match (want, case.get("core").and_then(|c| c.get("error"))) {
        (Want::Exact, Some(error)) => string(get(error, "message")),
        _ => return rows.stringify(),
    };
    let mut rows = rows.as_array().unwrap().to_vec();
    assert_eq!(rows.len(), 1, "a deviation's one row");
    let row = &mut rows[0];
    row.set("status", JsValue::string("failed"));
    row.set("errorMessage", JsValue::string(message.as_str()));
    for field in ["reference", "bzzUrl", "tagUid", "batchIdUsed"] {
        row.set(field, JsValue::Null);
    }
    JsValue::Array(rows).stringify()
}

fn count(step: V<'_, '_>, name: &str) -> usize {
    step.get("events")
        .map(|e| e.children().filter(|e| e.get(name).is_some()).count())
        .unwrap_or(0)
}

/// Lines on a marker file (none when it isn't there).
fn lines(path: &Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |t| t.lines().count())
}

/// A core whose grants and stores have moved, its vault the test
/// mnemonic's and unlocked, the signatures counted at `marker`.
fn signing_main(marker: &Path, env: &[(&str, &str)]) -> Main {
    let mut hooks = vec![(
        "FREEDOM_CORED_TEST_SWARM_SIGN_MARKER",
        marker.to_str().unwrap(),
    )];
    hooks.extend_from_slice(env);
    let mut main = swarm_world::main_with(&["swarm"], &hooks);
    main.import_vault();
    main
}

/// What a group's run counted.
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    cases: usize,
    played: usize,
    main_answered: usize,
    scenarios: usize,
}

/// Plays every case of `group`'s methods through `main`.
fn play_group(main: &mut Main, marker: &Path, group: &[&str]) -> Counts {
    let text = logic::text_of("swarm.json");
    let index = Index::new(&text).unwrap();
    let grammar_text = logic::text_of("swarm-grammar.json");
    let grammar_index = Index::new(&grammar_text).unwrap();
    let grammar = grammar_index.root();
    let keys_text = logic::text_of("keys.json");
    let keys_index = Index::new(&keys_text).unwrap();
    let keys = logic::keys(&keys_index);
    let scenarios = logic::scenarios(grammar);
    let root = main.core.grant_root.clone();
    let mut vault = Vault { unlocked: true };
    let mut counts = Counts::default();
    let mut scenarios_used = BTreeSet::new();
    let mut left_out_seen = BTreeSet::new();
    for case in get(index.root(), "methods").children() {
        let id = string(get(case, "id"));
        let steps: Vec<_> = get(case, "steps").children().collect();
        let methods: Vec<Option<String>> =
            steps.iter().map(|s| s.get("method").map(string)).collect();
        if !methods
            .iter()
            .any(|m| m.as_ref().is_some_and(|m| group.contains(&m.as_str())))
        {
            continue;
        }
        if let Some((_, why)) = LEFT_OUT.iter().find(|(l, _)| *l == id) {
            assert!(!why.is_empty());
            left_out_seen.insert(id.clone());
            continue;
        }
        assert!(
            methods
                .iter()
                .all(|m| m.as_ref().is_some_and(|m| group.contains(&m.as_str()))),
            "{id}: a case that mixes in another group's method"
        );
        counts.cases += 1;
        let deviation = case.get("deviation").map(string);
        let want = match &deviation {
            Some(d) => core_answer(d, get(case, "core")),
            None => Want::Reference,
        };
        let origin = logic::js(get(case, "origin"));
        let feeds = group == FEEDS;
        let mut script = Script {
            world: logic::TestWorld::of(case),
            node: if feeds {
                logic::Node::new()
            } else {
                logic::Node::of(case, &keys)
            },
            readiness: logic::publish_readiness(case),
            subscribe_check: None,
            key: origin.clone(),
            naming: None,
            parts: BTreeMap::new(),
            write_node: feeds.then(|| WriteNode::of(case, &keys)),
        };
        let mut world = json!({
            "reset": true,
            "clock": script.world.now,
            "grants": grants_json(&script.world),
        });
        if let Some(feeds) = case.get("feeds").filter(|f| f.kind() == Kind::String) {
            world["feeds"] = json!(string(feeds));
        }
        main.world(world);
        vault.set(main, get(case, "vault").is_str("unlocked"));
        let mut first = true;
        for (k, step) in steps.iter().enumerate() {
            let sid = if steps.len() > 1 {
                format!("{id}/{k}")
            } else {
                id.clone()
            };
            if let Some(clock) = step.get("clock") {
                script.world.now = number(clock) as u64;
                main.world(json!({ "clock": script.world.now }));
            }
            let Some(handoff) = logic::handoff(*step, &origin, &mut script.world) else {
                assert_eq!(get(*step, "requests").children().count(), 0, "{sid}");
                counts.main_answered += 1;
                continue;
            };
            let name = handoff.name.clone().unwrap();
            main_writes(
                main,
                &mut vault,
                &mut script,
                case,
                *step,
                handoff.key.as_str(),
                first,
            );
            first = false;
            script.key = handoff.key.clone();
            script.parts = parts_of(*step);
            let approval = approval_of(&name, *step)
                .map_or(String::new(), |a| format!(r#","approval":"{a}""#));
            let request = format!(
                r#"{{"method":{{"string":{}}},"params":{}{approval}}}"#,
                serde_json::to_string(&name).unwrap(),
                wire_typed(get(*step, "params"))
            );
            let signed_before = lines(marker);
            let played = main.play(&mut script, &page(handoff.key.as_str()), &request);
            counts.played += 1;

            let last = k + 1 == steps.len();
            logic::check_outcome(&sid, want, last, case, *step, &played.outcome);
            let row = row_of(&name);
            logic::check_row_shape(&sid, grammar, row, &played.ran());
            let earlier = last
                && (want == Want::Cancelled
                    || (want == Want::Exact && get(case, "core").get("error").is_some()));
            match scenarios.get(&sid) {
                Some(_) if case.get("core_before").is_some() => {
                    assert!(played.calls.is_empty() && played.ready.is_empty(), "{sid}");
                    scenarios_used.insert(sid.clone());
                }
                Some(scenario) => {
                    assert!(get(*scenario, "row").is_str(row), "{sid}");
                    check_calls(&sid, *scenario, &played, earlier);
                    scenarios_used.insert(sid.clone());
                }
                // A call main answered `stopped` never reached the node.
                None => assert!(
                    played.calls.is_empty() || script.node.stopped,
                    "{sid}: calls, and no honest scenario"
                ),
            }
            // The vault signed what the reference signed: as many SOCs
            // (each the scenario's, by its signature on the upload).
            let signed = lines(marker) - signed_before;
            let wanted = count(*step, "sign_soc");
            if earlier {
                assert!(signed <= wanted, "{sid}: signatures");
            } else {
                assert_eq!(signed, wanted, "{sid}: signatures");
            }
            if want == Want::Cancelled && last {
                assert_eq!(signed, 0, "{sid}: nothing signed");
                assert_eq!(played.soc_posts, 0, "{sid}: nothing uploaded");
            }
        }
        // The stores after, as the core left them on disk.
        let feeds_file = root.join("swarm-feeds.json");
        match get(case, "after")
            .get("feeds")
            .filter(|f| f.kind() == Kind::String)
        {
            Some(want) => assert_eq!(
                std::fs::read_to_string(&feeds_file).unwrap(),
                string(want),
                "{id}: swarm-feeds.json"
            ),
            None => assert!(!feeds_file.exists(), "{id}: no swarm-feeds.json"),
        }
        let expected = if feeds {
            expected_feed_history(case, want)
        } else {
            expected_publish_history(case, want)
        };
        assert_eq!(history_of(&root), expected, "{id}: the history");
    }
    let left_out: BTreeSet<String> = if group == FEEDS {
        LEFT_OUT.iter().map(|(id, _)| (*id).to_owned()).collect()
    } else {
        BTreeSet::new()
    };
    assert_eq!(left_out_seen, left_out, "every case left out exists");
    // Every honest scenario of the group's rows is one a step played.
    for (sid, scenario) in &scenarios {
        let from = string(get(*scenario, "from"));
        let Some(case_id) = from.strip_prefix("methods/") else {
            continue;
        };
        let row = string(get(*scenario, "row"));
        if !group.iter().any(|m| row_of(m) == row) || left_out.contains(case_id) {
            continue;
        }
        assert!(
            scenarios_used.contains(sid),
            "{sid}: an honest scenario no step played"
        );
    }
    counts.scenarios = scenarios_used.len();
    counts
}

fn marker_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("signed")
}

#[test]
fn every_publish_case_plays_through_the_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let marker = marker_in(&dir);
    let mut main = signing_main(&marker, &[]);
    let counts = play_group(&mut main, &marker, &PUBLISH);
    assert_eq!(
        counts,
        Counts {
            cases: 178,
            played: 177,
            main_answered: 10,
            scenarios: 86,
        }
    );
    assert_eq!(lines(&marker), 0, "an upload signs nothing");
}

#[test]
fn every_feed_and_soc_case_plays_through_the_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let marker = marker_in(&dir);
    let mut main = signing_main(&marker, &[]);
    let counts = play_group(&mut main, &marker, &FEEDS);
    assert_eq!(
        counts,
        Counts {
            cases: 191,
            played: 182,
            main_answered: 11,
            scenarios: 100,
        }
    );
    assert!(lines(&marker) > 50, "{}", lines(&marker));
}
