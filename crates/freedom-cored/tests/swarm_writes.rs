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
use fc_swarm_provider::machine::{Body, Outcome};
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

/// A case's world, set in the core afresh (D11): its clock, grants and
/// `swarm-feeds.json`, a new history, the vault as the case has it; and
/// main's script for it (the feed writes' node for `feeds`).
fn set_up(
    main: &mut Main,
    vault: &mut Vault,
    case: V<'_, '_>,
    keys: &logic::Keys,
    feeds: bool,
) -> Script {
    let script = Script {
        world: logic::TestWorld::of(case),
        node: if feeds {
            logic::Node::new()
        } else {
            logic::Node::of(case, keys)
        },
        readiness: logic::publish_readiness(case),
        subscribe_check: None,
        key: logic::js(get(case, "origin")),
        naming: None,
        parts: BTreeMap::new(),
        write_node: feeds.then(|| WriteNode::of(case, keys)),
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
    script
}

/// A step's `swarm.request` params, its parts in the script.
fn prepare(script: &mut Script, step: V<'_, '_>, handoff: &logic::Handoff) -> String {
    let name = handoff.name.clone().unwrap();
    script.key = handoff.key.clone();
    script.parts = parts_of(step);
    let approval =
        approval_of(&name, step).map_or(String::new(), |a| format!(r#","approval":"{a}""#));
    format!(
        r#"{{"method":{{"string":{}}},"params":{}{approval}}}"#,
        serde_json::to_string(&name).unwrap(),
        wire_typed(get(step, "params"))
    )
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
        let mut script = set_up(main, &mut vault, case, &keys, feeds);
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
            let request = prepare(&mut script, *step, &handoff);
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

// ---------------------------------------------------------------------------
// The stores' own paths through the core.

/// The vectors, read once for a test.
struct Vectors {
    text: String,
    keys: String,
}

impl Vectors {
    fn read() -> Vectors {
        Vectors {
            text: logic::text_of("swarm.json"),
            keys: logic::text_of("keys.json"),
        }
    }
}

fn case_of<'i, 't>(index: &'i Index<'t>, id: &str) -> V<'i, 't> {
    get(index.root(), "methods")
        .children()
        .find(|c| get(*c, "id").is_str(id))
        .unwrap_or_else(|| panic!("no case {id}"))
}

/// A one-step case staged as `play_group` stages it, up to its request:
/// main's script, the request's params and the page's key.
fn staged(
    main: &mut Main,
    vault: &mut Vault,
    case: V<'_, '_>,
    keys: &logic::Keys,
    feeds: bool,
) -> (Script, String, String) {
    let mut script = set_up(main, vault, case, keys, feeds);
    let step = get(case, "steps").children().next().unwrap();
    let origin = logic::js(get(case, "origin"));
    let handoff = logic::handoff(step, &origin, &mut script.world).unwrap();
    main_writes(
        main,
        vault,
        &mut script,
        case,
        step,
        handoff.key.as_str(),
        true,
    );
    let request = prepare(&mut script, step, &handoff);
    (script, request, handoff.key.as_str().to_owned())
}

fn failure(outcome: &Outcome) -> (i32, String) {
    match outcome {
        Outcome::Error(f) => (f.code, f.message.as_str().to_owned()),
        other => panic!("{other:?}"),
    }
}

/// Before `core.hello` names `swarm_stores` (D3), every method that touches
/// the stores answers `not_moved`, and the core reads and writes none of
/// them: a `swarm-feeds.json` that doesn't parse stays as it is, nothing is
/// kept aside, and no history or manifest file appears.
#[test]
fn not_moved_before_the_move_writes_nothing() {
    let mut main = swarm_world::main_stores(&["swarm"], &[], &[]);
    let root = main.core.grant_root.clone();
    std::fs::write(root.join("swarm-feeds.json"), "{not json").unwrap();
    main.world(json!({
        "reset": true,
        "grants": { "https://app.example": {
            "origin": "https://app.example", "connectedAt": 1, "lastUsed": 1,
            "autoApprove": { "publish": false, "feeds": false, "signing": false, "messaging": false },
        } },
    }));
    for method in [
        "swarm_listFeeds",
        "swarm_readFeedEntry",
        "swarm_publishData",
        "swarm_publishFiles",
        "swarm_publishChunk",
        "swarm_createFeed",
        "swarm_updateFeed",
        "swarm_writeFeedEntry",
        "swarm_writeSingleOwnerChunk",
        "swarm_getSigningIdentity",
    ] {
        let request = format!(
            r#"{{"method":{{"string":"{method}"}},"params":{{"object":[["name",{{"string":"blog"}}]]}},"approval":"user"}}"#
        );
        let id = main.request(&page("https://app.example"), &request);
        let answer = main.core.response(id);
        assert_eq!(answer["error"]["code"], "not_moved", "{method}: {answer}");
        assert_eq!(answer["error"]["data"], json!({ "store": "swarm_stores" }));
    }
    let mut names: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("swarm-") || n.starts_with("publish-history"))
        .collect();
    names.sort();
    assert_eq!(names, ["swarm-feeds.json"]);
    assert_eq!(
        std::fs::read_to_string(root.join("swarm-feeds.json")).unwrap(),
        "{not json"
    );
    // The hello's echo leaves the name out.
    let mut main = swarm_world::main_stores(&["swarm"], &["swarm_stores"], &[]);
    assert!(main.world(json!({}))["memory"].is_number());
}

/// A failure at each step of `swarm-feeds.json`'s durable write: before
/// the rename (`write`, `fsync`, `rename`) the change fails for its caller
/// with the store's text and the file and the store stay as they were;
/// at the directory's flush the change is in place, not durable, and made.
/// A history statement that fails fails its request with its own text,
/// and its row isn't there.
#[test]
fn a_failure_at_each_write_step() {
    let dir = tempfile::tempdir().unwrap();
    let marker = marker_in(&dir);
    let hooks = dir.path().join("fail");
    let mut main = signing_main(
        &marker,
        &[(
            "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL",
            hooks.to_str().unwrap(),
        )],
    );
    let root = main.core.grant_root.clone();
    let vectors = Vectors::read();
    let index = Index::new(&vectors.text).unwrap();
    let keys_index = Index::new(&vectors.keys).unwrap();
    let keys = logic::keys(&keys_index);
    let mut vault = Vault { unlocked: true };
    let case = case_of(&index, "create-feed-bee-wallet");
    let after = string(get(get(case, "after"), "feeds"));
    for step in ["write", "fsync", "rename", "flush"] {
        let (mut script, request, key) = staged(&mut main, &mut vault, case, &keys, true);
        let before = std::fs::read_to_string(root.join("swarm-feeds.json")).unwrap();
        std::fs::write(&hooks, format!("swarm_feeds:{step}\n")).unwrap();
        let played = main.play(&mut script, &page(&key), &request);
        std::fs::remove_file(&hooks).unwrap();
        let text = std::fs::read_to_string(root.join("swarm-feeds.json")).unwrap();
        if step == "flush" {
            assert!(matches!(played.outcome, Outcome::Result(_)), "{step}");
            assert_eq!(text, after, "{step}");
        } else {
            assert_eq!(
                failure(&played.outcome),
                (
                    -32603,
                    "The Swarm feed store could not be written".to_owned()
                ),
                "{step}"
            );
            assert_eq!(text, before, "{step}: the file as it was");
            // ...and the store too: the same request, the write working,
            // makes the reference's change.
            let (mut script, request, key) = staged(&mut main, &mut vault, case, &keys, true);
            let played = main.play(&mut script, &page(&key), &request);
            assert!(matches!(played.outcome, Outcome::Result(_)), "{step}");
            assert_eq!(
                std::fs::read_to_string(root.join("swarm-feeds.json")).unwrap(),
                after,
                "{step}"
            );
        }
    }

    // The history: its insert fails, so the upload doesn't start.
    let case = case_of(&index, "publish-chunk-one-byte");
    let (mut script, request, key) = staged(&mut main, &mut vault, case, &keys, false);
    std::fs::write(&hooks, "swarm_history:write\n").unwrap();
    let played = main.play(&mut script, &page(&key), &request);
    std::fs::remove_file(&hooks).unwrap();
    assert_eq!(
        failure(&played.outcome),
        (
            -32603,
            "The publish history could not be read or written".to_owned()
        )
    );
    assert!(
        played.calls.iter().all(|c| c.call.method() == "GET"),
        "nothing uploaded"
    );
    assert_eq!(history_of(&root), "[]");
}

/// A feed store near its 16 MiB: a change that would pass it is refused,
/// `store_full`, -32603 `Swarm feed store is full`, and the file and the
/// store stay as they were (design 0015, Budgets).
#[test]
fn a_full_feed_store_refuses_the_record() {
    use fc_swarm_provider::stores::feeds::{FeedStore, MAX_FILE_BYTES};
    let dir = tempfile::tempdir().unwrap();
    let marker = marker_in(&dir);
    let mut main = signing_main(&marker, &[]);
    let root = main.core.grant_root.clone();
    let vectors = Vectors::read();
    let index = Index::new(&vectors.text).unwrap();
    let keys_index = Index::new(&vectors.keys).unwrap();
    let keys = logic::keys(&keys_index);
    let mut vault = Vault { unlocked: true };
    let case = case_of(&index, "create-feed-bee-wallet");
    let (mut script, request, key) = staged(&mut main, &mut vault, case, &keys, true);
    // Another site's feed padded to leave the store 150 bytes below its
    // bound: less than the new feed's record.
    let file = root.join("swarm-feeds.json");
    let padded = |pad: usize| {
        let mut store = fc_json::parse(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let entry = fc_json::parse(&format!(
            r#"{{"activeIdentityId":"bee-wallet","identities":{{"bee-wallet":{{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null}}}},"feedGranted":false,"grantedAt":1,"feeds":{{"pad":{{"topic":"{}"}}}}}}"#,
            "a".repeat(pad)
        ))
        .unwrap();
        let mut origins = store.get("origins").unwrap().clone();
        origins.set("https://pad.example", entry);
        store.set("origins", origins);
        FeedStore::load(Some(store.stringify().as_bytes()), 0, |_| false)
            .store
            .text()
            .unwrap()
    };
    let base = padded(0).len();
    let text = padded(MAX_FILE_BYTES - base - 150);
    assert_eq!(text.len(), MAX_FILE_BYTES - 150);
    std::fs::write(&file, &text).unwrap();
    main.world(json!({ "reload": true }));
    let played = main.play(&mut script, &page(&key), &request);
    assert_eq!(
        failure(&played.outcome),
        (-32603, "Swarm feed store is full".to_owned())
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
}

/// A row left `uploading` when the core goes mid-upload is `failed` with
/// `interrupted by app exit` once the next core opens the history (the
/// reference's `sweepOrphans`).
#[test]
fn a_restart_sweeps_a_row_left_uploading() {
    let mut main = swarm_world::main();
    let root = main.core.grant_root.clone();
    main.world(json!({
        "reset": true,
        "grants": { "https://app.example": {
            "origin": "https://app.example", "connectedAt": 1, "lastUsed": 1,
            "autoApprove": { "publish": false, "feeds": false, "signing": false, "messaging": false },
        } },
    }));
    // An upload whose node never answers.
    main.request(
        &page("https://app.example"),
        r#"{"method":{"string":"swarm_publishData"},"params":{"object":[["data",{"string":"hello"}],["contentType",{"string":"text/plain"}]]},"approval":"user"}"#,
    );
    loop {
        let message = main.recv();
        let id = message["id"].as_u64().unwrap();
        match message["method"].as_str() {
            Some("shell.swarm_ready") => main.answer(id, json!({ "ok": true })),
            Some("approval.recheck") => main.answer(id, json!({ "live": true, "agent": false })),
            Some("shell.swarm_api") if message["params"]["form"] == "stamps" => main.answer(
                id,
                json!({ "status": 200, "status_text": "OK", "headers": [],
                    "body_base64": base64_of(STAMPS.as_bytes()) }),
            ),
            Some("shell.swarm_api") => break,
            _ => panic!("{message}"),
        }
    }
    let rows = history_of(&root);
    assert!(rows.contains(r#""status":"uploading""#), "{rows}");
    let mut main = main.restart(&[]);
    // The thread has loaded the stores once it answers.
    main.world(json!({}));
    let rows = history_of(&root);
    assert!(rows.contains(r#""status":"failed""#), "{rows}");
    assert!(
        rows.contains(r#""errorMessage":"interrupted by app exit""#),
        "{rows}"
    );
}

/// One usable batch, as the node lists it.
const STAMPS: &str = r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#;

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A moved profile (design 0015, D10; 0017, C5): the legacy
/// `publish-history.json` at the profile's root is copied into the Freedom
/// root before `confine`, imported from the copy into the history there,
/// and the copy renamed `.migrated`; the next start drops the original.
#[test]
fn a_moved_profile_imports_its_publish_history_from_a_copy() {
    let (_root, data, locks) = common::dirs();
    let user_data = common::default_grant_root(&data);
    let grant_root = user_data.join("freedom");
    std::fs::create_dir_all(&grant_root).unwrap();
    let legacy = r#"{"entries":[{"type":"file","name":"a.txt","status":"completed","reference":"aa","timestamp":"2026-01-01T00:00:00.000Z"}]}"#;
    std::fs::write(user_data.join("publish-history.json"), legacy).unwrap();
    let start = || {
        let mut core = common::spawn_env(
            "serve",
            &data,
            &locks,
            &[
                "--grant-root",
                grant_root.to_str().unwrap(),
                "--user-data-dir",
                user_data.to_str().unwrap(),
            ],
            &[("FREEDOM_CORED_TEST_METHODS", "1")],
        );
        let hello = core.call_shell(
            1,
            "core.hello",
            json!({
                "protocol": 2, "shell_version": "test", "auto_lock_ms": 900_000,
                "frames": ["stream"], "grant_root": grant_root,
                "user_data_dir": user_data, "store_moved": ["swarm_stores"],
            }),
        );
        assert_eq!(
            hello["result"]["store_moved"],
            json!(["swarm_stores"]),
            "{hello}"
        );
        // The swarm thread has loaded the stores once it answers.
        let world = core.call_shell(2, "test.swarm_world", json!({}));
        assert!(world["result"].is_object(), "{world}");
        core
    };
    let core = start();
    let rows = history_of(&grant_root);
    assert!(rows.contains(r#""name":"a.txt""#), "{rows}");
    assert!(!user_data.join("publish-history.sqlite").exists());
    assert_eq!(
        std::fs::read_to_string(user_data.join("publish-history.json")).unwrap(),
        legacy
    );
    assert!(!grant_root.join("publish-history.json").exists());
    assert_eq!(
        std::fs::read_to_string(grant_root.join("publish-history.json.migrated")).unwrap(),
        legacy
    );
    drop(core);
    let _core = start();
    assert!(!user_data.join("publish-history.json").exists());
    assert_eq!(history_of(&grant_root).matches("a.txt").count(), 1);
}
