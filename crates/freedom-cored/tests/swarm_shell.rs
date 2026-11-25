//! Main's own Swarm methods through the core (design 0015, SWM-4 PR 9):
//! the real binary, its Swarm grants and stores moved, and the test as
//! main ([`swarm_world`]).
//!
//! - **Every `stores` case** of `vectors/swarm.json` (27 feeds, 17
//!   manifests, 10 history) played through `swarm.identities`,
//!   `swarm.manifest` and `swarm.history` over one core (D11), each call in
//!   its wire form: the feed prompt's and the chrome's ops, the vault's
//!   owners from the core's own vault (the test mnemonic's), a check's
//!   manifest fetched by main through `shell.swarm_manifest` (D6). The
//!   method machines' own feed changes go through the keeper as
//!   `test.swarm_feed_change` makes them; their reads are read from the
//!   file the core left; the publish machines' history statements are run
//!   on the core's database directly. Each case: every answer (the case's
//!   `core` where a deviation changes it), the files the core left on disk,
//!   the Swarm grants as `approval.grants` reads them, the history's rows.
//! - **Main's own node methods** (`swarm.publish`, `swarm.feed`,
//!   `swarm.stamps`, `swarm.upload_status`): a picked file and a
//!   collection published, their parts streamed through `shell.swarm_part`
//!   and their bodies through `swarm.body`, with their history rows; a
//!   picked file whose read fails; `swarm.feed`'s create, an update with
//!   `min_index` and a read; the batches and a tag.
//! - **Callers, admission and bounds:** the method table's callers
//!   (`forbidden`), an op only main makes refused to the chrome,
//!   admission's `busy` for main, `shell.swarm_manifest`'s answers and its
//!   bound, and `approval.changed` after a projection's write.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod swarm_world;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fc_json::index::{Index, KeyOrder};
use fc_json::{JsString, JsValue};
use fc_swarm_provider::machine::{Event, Failed, Form, NodeCall, Reply};
use fc_swarm_provider::stores::feeds::{self, FeedStore};
use fc_swarm_provider::stores::history::{self, Bind, Cell, Statement};
use fc_swarm_provider::stores::manifests;
use fc_swarm_provider::value::Value as Typed;
use serde_json::{Value, json};
use swarm_world::logic::{self, get};
use swarm_world::{Main, OwnMain};

/// The cases' clock; the history's reopen is a second later.
const T0: u64 = 1_767_225_600_123;

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn stores_section() -> Vec<JsValue> {
    let text = std::fs::read_to_string(vectors_root().join("swarm.json")).unwrap();
    let index = Index::new(&text).unwrap();
    let stores = fc_json::parse(index.root().get("stores").unwrap().raw()).unwrap();
    stores.as_array().unwrap().to_vec()
}

fn field<'v>(value: &'v JsValue, key: &str) -> &'v JsValue {
    value
        .get(key)
        .unwrap_or_else(|| panic!("no {key:?} in {}", short(value)))
}

fn short(value: &JsValue) -> String {
    value.stringify().chars().take(300).collect()
}

fn str_of(value: &JsValue) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {}", short(value)))
}

/// `formats.typed`'s values, as JavaScript holds them.
fn typed(value: &JsValue) -> JsValue {
    let JsValue::Object(props) = value else {
        panic!("not a typed value: {}", short(value));
    };
    let [(tag, inner)] = props.as_slice() else {
        panic!("not one typed value: {}", short(value));
    };
    match tag.as_str() {
        "string" => inner.clone(),
        "string_json" => fc_json::parse(str_of(inner)).unwrap(),
        "number" => JsValue::Number(str_of(inner).parse().unwrap()),
        "boolean" => inner.clone(),
        "null" => JsValue::Null,
        "undefined" => JsValue::Undefined,
        "array" => JsValue::Array(inner.as_array().unwrap().iter().map(typed).collect()),
        "object" => JsValue::Object(
            inner
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    let pair = pair.as_array().unwrap();
                    (JsString::from(str_of(&pair[0])), typed(&pair[1]))
                })
                .collect(),
        ),
        other => panic!("a typed form the stores don't use: {other}"),
    }
}

/// A JavaScript value in the typed form, as main writes an op's member.
fn to_typed(value: &JsValue) -> JsValue {
    let mut out = JsValue::Object(Vec::new());
    match value {
        JsValue::Undefined => out.set("undefined", JsValue::Bool(true)),
        JsValue::Null => out.set("null", JsValue::Bool(true)),
        JsValue::Bool(b) => out.set("boolean", JsValue::Bool(*b)),
        JsValue::Number(n) => out.set("number", JsValue::string(fc_json::number_to_string(*n))),
        JsValue::String(s) => out.set("string", JsValue::String(s.clone())),
        JsValue::Array(items) => out.set(
            "array",
            JsValue::Array(items.iter().map(to_typed).collect()),
        ),
        JsValue::Object(members) => out.set(
            "object",
            JsValue::Array(
                members
                    .iter()
                    .map(|(k, v)| JsValue::Array(vec![JsValue::String(k.clone()), to_typed(v)]))
                    .collect(),
            ),
        ),
    }
    out
}

/// A JavaScript value as JSON main sends (no `undefined` inside it).
fn json_of(value: &JsValue) -> Value {
    serde_json::from_str(&value.stringify()).unwrap()
}

/// An op's params: `op` and its members, typed.
fn op_params(op: &str, members: &[(&str, JsValue)]) -> Value {
    let mut out = JsValue::Object(Vec::new());
    out.set("op", JsValue::string(op));
    for (name, value) in members {
        out.set(*name, to_typed(value));
    }
    json_of(&out)
}

/// A typed answer as a JSON value (the stores' answers hold no BigInt or
/// bytes).
fn value_js(value: &Typed) -> JsValue {
    match value {
        Typed::Undefined => JsValue::Undefined,
        Typed::Null => JsValue::Null,
        Typed::Bool(b) => JsValue::Bool(*b),
        Typed::Number(n) => JsValue::Number(*n),
        Typed::String(s) => JsValue::String(s.clone()),
        Typed::Array(items) => JsValue::Array(
            items
                .iter()
                .map(|i| value_js(i.as_ref().unwrap()))
                .collect(),
        ),
        Typed::Object(members) => JsValue::Object(
            members
                .iter()
                .map(|(k, v)| (k.clone(), value_js(v)))
                .collect(),
        ),
        other => panic!("a store answer holds {other:?}"),
    }
}

/// What main read: an answer (`result_typed`), what the method threw
/// (`error_typed`), or a protocol error's code.
#[derive(Debug, Clone, PartialEq)]
enum Got {
    Value(JsValue),
    Thrown(JsValue),
    Error(String),
}

fn got(message: &Value) -> Got {
    if let Some(error) = message.get("error") {
        return Got::Error(error["code"].as_str().unwrap().to_owned());
    }
    let read = |v: &Value| {
        let parsed = fc_json::parse(&v.to_string()).unwrap();
        value_js(&Typed::from_typed(&parsed).unwrap_or_else(|e| panic!("{e}: {v}")))
    };
    let result = &message["result"];
    if let Some(value) = result.get("result_typed") {
        return Got::Value(read(value));
    }
    Got::Thrown(read(&result["error_typed"]))
}

#[derive(Debug)]
enum Expected {
    Value(JsValue),
    Error(JsValue),
}

fn expected(step: &JsValue) -> Expected {
    if let Some(result) = step.get("result") {
        Expected::Value(result.clone())
    } else if let Some(result) = step.get("result_typed") {
        Expected::Value(typed(result))
    } else if let Some(error) = step.get("error") {
        Expected::Error(error.clone())
    } else {
        panic!("no answer in {}", short(step));
    }
}

fn assert_answer(case: &str, step: usize, got: &Got, want: &Expected) {
    match (got, want) {
        (Got::Value(got), Expected::Value(want)) => {
            if matches!(want, JsValue::Undefined) {
                assert_eq!(got, &JsValue::Undefined, "{case} step {step}");
            } else {
                assert_eq!(got.stringify(), want.stringify(), "{case} step {step}");
            }
        }
        (Got::Thrown(got), Expected::Error(want)) => {
            assert_eq!(got.get("name"), want.get("name"), "{case} step {step}");
            assert_eq!(
                got.get("message"),
                want.get("message"),
                "{case} step {step}"
            );
            assert_eq!(got.get("code"), want.get("code"), "{case} step {step}");
        }
        (got, want) => panic!("{case} step {step}: got {got:?}, want {want:?}"),
    }
}

type Dir = BTreeMap<String, String>;

fn text_map(value: &JsValue) -> Dir {
    match value {
        JsValue::Object(props) => props
            .iter()
            .map(|(name, text)| (name.as_str().to_owned(), str_of(text).to_owned()))
            .collect(),
        JsValue::Null => Dir::new(),
        other => panic!("not an object: {}", short(other)),
    }
}

fn core_of(case: &JsValue) -> Option<&JsValue> {
    case.get("core")
        .filter(|core| matches!(core, JsValue::Object(_)))
}

/// The files in `root` whose name `keep` takes, as text.
fn files_in(root: &Path, keep: impl Fn(&str) -> bool) -> Dir {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            keep(&name).then(|| {
                let text = std::fs::read_to_string(root.join(&name)).unwrap();
                (name, text)
            })
        })
        .collect()
}

/// The stores' files a case leaves, removed before the next.
fn clean(root: &Path) {
    for (name, _) in files_in(root, |name| {
        name.starts_with("swarm-feeds")
            || name.starts_with("swarm-manifest-grants")
            || name.starts_with("swarm-permissions")
            || name.starts_with("publish-history.json")
    }) {
        std::fs::remove_file(root.join(name)).unwrap();
    }
}

/// The core with its stores and grants moved, and its vault the test
/// mnemonic's (keys.json's `abandon-12`, the vectors' owners).
fn store_main() -> Main {
    let mut main = swarm_world::main();
    main.import_vault();
    main
}

// --- the stores' cases -----------------------------------------------------------

#[test]
fn every_stores_case_through_the_pipe() {
    let cases = stores_section();
    let mut main = store_main();
    let mut played: BTreeMap<String, usize> = BTreeMap::new();
    for case in &cases {
        let kind = str_of(field(case, "kind"));
        match kind {
            "feeds" => play_feeds(&mut main, case),
            "manifests" => play_manifests(&mut main, case),
            "history" => play_history(&mut main, case),
            other => panic!("kind {other}"),
        }
        *played.entry(kind.to_owned()).or_default() += 1;
    }
    let counts: Vec<(&str, usize)> = played.iter().map(|(k, n)| (k.as_str(), *n)).collect();
    assert_eq!(counts, [("feeds", 27), ("history", 10), ("manifests", 17)]);
}

/// The index-allocation case's core side: the new identity at index 1.
const ALLOCATION_CORE: &str = "allocates index 1: the larger of nextPublisherKeyIndex (0) and one past every stored index (0)";

fn reindexed(entry: &JsValue) -> JsValue {
    let text = entry
        .stringify()
        .replace("app-scoped:0", "app-scoped:1")
        .replace("\"publisherKeyIndex\":0", "\"publisherKeyIndex\":1")
        .replace("App-scoped identity 1", "App-scoped identity 2");
    fc_json::parse(&text).unwrap()
}

fn core_allocation_file(file: &str) -> String {
    let mut root = fc_json::parse(file).unwrap();
    root.set("nextPublisherKeyIndex", JsValue::Number(2.0));
    let origins = root.get_mut("origins").unwrap();
    let app = origins.get("https://app.example").unwrap().clone();
    origins.set("https://app.example", reindexed(&app));
    root.stringify_pretty()
}

/// The world a case starts in: the stores' files written, then read again
/// as a start reads them, the grants set, the clock fixed.
fn set_up(main: &mut Main, files: &Dir, grants: &JsValue, clock: u64) {
    let root = main.core.grant_root.clone();
    main.world(json!({ "reset": true, "clock": clock }));
    clean(&root);
    for (name, text) in files {
        std::fs::write(root.join(name), text).unwrap();
    }
    main.world(json!({ "reload": true, "grants": json_of(grants) }));
}

/// The feed store as the core left it on disk.
fn feeds_on_disk(root: &Path) -> FeedStore {
    let file = std::fs::read(root.join(feeds::FILE_NAME)).ok();
    FeedStore::load(file.as_deref(), T0, |_| false).store
}

/// A method machine's feed change through the core's keeper
/// (`test.swarm_feed_change`): its value, or its caller's error text.
fn feed_change(main: &mut Main, change: Value) -> Got {
    let answer = main.feed_change(change);
    match answer.get("value") {
        Some(value) => Got::Value(fc_json::parse(&value.to_string()).unwrap()),
        None => Got::Error(answer["error"].as_str().unwrap().to_owned()),
    }
}

fn play_feeds(main: &mut Main, case: &JsValue) {
    let id = str_of(field(case, "id"));
    let root = main.core.grant_root.clone();
    let mut dir = Dir::new();
    if let Some(before) = field(case, "before").as_str() {
        dir.insert(feeds::FILE_NAME.to_owned(), before.to_owned());
    }
    if let Some(files) = case.get("before_files") {
        dir.extend(text_map(files));
    }
    set_up(main, &dir, &JsValue::Object(Vec::new()), T0);
    let locked = case.get("vault").and_then(JsValue::as_str) == Some("locked");
    if locked {
        main.set_vault(false);
    }
    let allocation = case.get("deviation").and_then(JsValue::as_str) == Some("index-allocation");
    let core = core_of(case);
    let core_ops = core.map(|core| field(core, "ops").as_array().unwrap());
    let ops = field(case, "ops").as_array().unwrap();
    for (n, op) in ops.iter().enumerate() {
        let args = typed(field(op, "args"));
        let args = args.as_array().unwrap();
        let arg = |i: usize| args.get(i).cloned().unwrap_or(JsValue::Undefined);
        let key = || match &arg(0) {
            JsValue::String(s) => s.clone(),
            other => panic!("{id}: origin {}", short(other)),
        };
        let name = || match &arg(1) {
            JsValue::String(s) => s.clone(),
            other => panic!("{id}: name {}", short(other)),
        };
        let mut want = match core_ops {
            Some(answers) => expected(&answers[n]),
            None => expected(op),
        };
        if allocation {
            assert_eq!(str_of(field(case, "core")), ALLOCATION_CORE, "{id}");
            if let Expected::Value(value) = &want {
                want = Expected::Value(reindexed(value));
            }
        }
        let call = |main: &mut Main, op: &str, members: &[(&str, JsValue)], caller: &str| {
            let mut own = OwnMain::new(|call, _| panic!("a store op called the node: {call:?}"));
            got(&main.play_own(
                &mut own,
                "swarm.identities",
                &op_params(op, members),
                caller,
            ))
        };
        let change = |main: &mut Main, change: Value| {
            let got = feed_change(main, change);
            // The keeper's refusal is its text, and the hook answers
            // `undefined` as `null`; the store answers the rest.
            match (&got, &want) {
                (Got::Error(text), Expected::Error(error)) => {
                    assert_eq!(
                        Some(text.as_str()),
                        field(error, "message").as_str(),
                        "{id} step {n}"
                    );
                    None
                }
                (Got::Value(JsValue::Null), Expected::Value(JsValue::Undefined)) => {
                    Some(Got::Value(JsValue::Undefined))
                }
                _ => Some(got),
            }
        };
        let got: Option<Got> = match str_of(field(op, "op")) {
            "getAllOriginEntries" => Some(call(main, "get-all-origins", &[], "chrome")),
            "getOriginIdentityStateWithOwners" => {
                let got = call(
                    main,
                    "getOriginIdentityStateWithOwners",
                    &[("key", arg(0))],
                    "shell",
                );
                let again = call(
                    main,
                    "get-origin-identities",
                    &[("origin", arg(0))],
                    "chrome",
                );
                assert_eq!(again, got, "{id} step {n}: the chrome's");
                Some(got)
            }
            "previewAppScopedIdentity" => Some(call(
                main,
                "previewAppScopedIdentity",
                &[("key", arg(0)), ("options", arg(1))],
                "shell",
            )),
            "createAppScopedIdentityAt" => Some(call(
                main,
                "createAppScopedIdentityAt",
                &[("key", arg(0)), ("index", arg(1)), ("options", arg(2))],
                "shell",
            )),
            "ensureAntWalletIdentity" => Some(call(
                main,
                "ensureAntWalletIdentity",
                &[("key", arg(0)), ("options", arg(1))],
                "shell",
            )),
            "activateIdentity" => Some(call(
                main,
                "activateIdentity",
                &[("key", arg(0)), ("identity_id", arg(1))],
                "shell",
            )),
            "grantFeedAccess"
                if arg(1).get("source").and_then(JsValue::as_str) == Some("manifest") =>
            {
                // A manifest's projection, made through the keeper.
                change(
                    main,
                    json!({ "op": "grantFeedAccess", "key": key().as_str() }),
                )
            }
            "grantFeedAccess" => {
                assert!(arg(1).get("source").is_none(), "{id}");
                Some(call(main, "grantFeedAccess", &[("key", arg(0))], "shell"))
            }
            "createAppScopedIdentity" => {
                assert!(arg(1).get("source").is_none(), "{id}");
                // The chrome's handler answers the state with owners; the
                // site's entry after is the reference's answer.
                let got = call(
                    main,
                    "create-app-scoped-identity",
                    &[("origin", arg(0)), ("options", arg(1))],
                    "chrome",
                );
                Some(match got {
                    Got::Value(_) => Got::Value(feeds_on_disk(&root).origin_entry(&key()).unwrap()),
                    other => other,
                })
            }
            "revokeFeedAccess" => {
                assert!(arg(1).get("source").is_none(), "{id}");
                let got = call(main, "revoke-feed-access", &[("origin", arg(0))], "chrome");
                Some(match got {
                    Got::Value(answer) => {
                        assert_eq!(answer, JsValue::Bool(true), "{id} step {n}");
                        Got::Value(JsValue::Undefined)
                    }
                    other => other,
                })
            }
            "setFeed" => change(
                main,
                json!({ "op": "setFeed", "key": key().as_str(), "name": name().as_str(), "data": json_of(&arg(2)) }),
            ),
            "updateFeedReference" => change(
                main,
                json!({ "op": "updateFeedReference", "key": key().as_str(), "name": name().as_str(), "reference": json_of(&arg(2)) }),
            ),
            "setOriginEntry" => change(
                main,
                json!({ "op": "setOriginEntry", "key": key().as_str(), "data": json_of(&arg(1)) }),
            ),
            "allocatePublisherKeyIndex" => {
                change(main, json!({ "op": "allocatePublisherKeyIndex" }))
            }
            "getFeed" => Some(Got::Value(
                feeds_on_disk(&root)
                    .feed(&key(), &name())
                    .unwrap_or(JsValue::Null),
            )),
            "getAllFeeds" => Some(Got::Value(feeds_on_disk(&root).all_feeds(&key()))),
            "isIdentitySharedWithOtherOrigins" => Some(Got::Value(JsValue::Bool(
                feeds_on_disk(&root).is_identity_shared_with_other_origins(&key(), &arg(1)),
            ))),
            other => panic!("{id}: feed-store operation {other}"),
        };
        if let Some(got) = got {
            assert_answer(id, n, &got, &want);
        }
    }
    if locked {
        main.set_vault(true);
    }
    let mut want_files = text_map(field(core.unwrap_or(case), "files"));
    if allocation {
        let file = want_files.get_mut(feeds::FILE_NAME).unwrap();
        *file = core_allocation_file(file);
    }
    assert_eq!(
        files_in(&root, |n| n.starts_with("swarm-feeds")),
        want_files,
        "{id}"
    );
}

/// `shell.swarm_manifest`'s answer for a manifest: its status, and at most
/// 8 KiB and a byte of its body, as main reads it.
fn fetched(status: u16, manifest: &[u8]) -> Value {
    let body = &manifest[..manifest.len().min(manifests::MAX_MANIFEST_BYTES + 1)];
    json!({ "status": status, "body_base64": fc_swarm_provider::value::encode_base64(body) })
}

/// The Swarm grants as `approval.grants` reads them, by site, each the
/// reads a manifest's projections make: its times, its rules, whether it
/// holds the messaging grant (the vectors' mirror writes `messaging: true`
/// where the file keeps `{ grantedAt }`, and `false` where the file has
/// none).
fn grants_read(main: &mut Main) -> BTreeMap<String, Value> {
    let id = main.id();
    let reply = main
        .core
        .call_shell(id, "approval.grants", json!({ "store": "swarm" }));
    reply["result"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| (record["origin"].as_str().unwrap().to_owned(), reads(record)))
        .collect()
}

fn reads(record: &Value) -> Value {
    let messaging = !matches!(&record["messaging"], Value::Null | Value::Bool(false));
    json!({
        "connectedAt": record["connectedAt"],
        "lastUsed": record["lastUsed"],
        "autoApprove": record["autoApprove"],
        "messaging": messaging,
    })
}

fn play_manifests(main: &mut Main, case: &JsValue) {
    let id = str_of(field(case, "id"));
    let root = main.core.grant_root.clone();
    let site = field(case, "site").clone();
    let site_text = str_of(&site).to_owned();
    let url = JsValue::string(format!("{site_text}/index.html"));
    let mut dir = Dir::new();
    if let Some(before) = field(case, "before").as_str() {
        dir.insert(manifests::FILE_NAME.to_owned(), before.to_owned());
    }
    if let Some(files) = case.get("before_files") {
        dir.extend(text_map(files));
    }
    if let Some(text) = field(case, "feeds").as_str() {
        dir.insert(feeds::FILE_NAME.to_owned(), text.to_owned());
    }
    set_up(main, &dir, field(case, "grants"), T0);
    let core = core_of(case);
    let steps = field(case, "steps").as_array().unwrap();
    let manifest_call = |main: &mut Main, params: Value, fetch: Option<(u16, Vec<u8>)>| {
        let fetches = std::cell::Cell::new(0);
        let site_text = site_text.clone();
        let mut own = OwnMain::new(|call, _| panic!("a manifest op called the node: {call:?}"));
        own.manifest = Box::new(|asked: &str| {
            assert_eq!(asked, format!("{site_text}/freedom-manifest.json"), "{id}");
            fetches.set(fetches.get() + 1);
            let (status, body) = fetch.clone().expect("a fetch");
            Some(fetched(status, &body))
        });
        let answer = got(&main.play_own(&mut own, "swarm.manifest", &params, "shell"));
        drop(own);
        assert!(fetches.get() <= 1, "{id}");
        answer
    };
    // store-shapes: neither the file nor its .bak copy is read, so every op
    // fails, and nothing is written.
    if let Some(load) = core.and_then(|core| core.get("load")) {
        assert_eq!(str_of(load), "unreadable", "{id}");
        let before = files_in(&root, |n| n.starts_with("swarm-"));
        for (n, step) in steps.iter().enumerate() {
            let params = match str_of(field(step, "op")) {
                "useIndividual" => op_params(
                    "use-individual",
                    &[
                        ("origin", site.clone()),
                        ("capability", field(step, "capability").clone()),
                    ],
                ),
                "get" => op_params("get", &[("origin", site.clone())]),
                other => panic!("{id}: {other}"),
            };
            let answer = manifest_call(main, params, None);
            let Got::Thrown(thrown) = answer else {
                panic!("{id} step {n}: {answer:?}");
            };
            assert_eq!(
                thrown.get("message").and_then(JsValue::as_str),
                Some("swarm-manifest-grants.json and its backup are unreadable"),
                "{id} step {n}"
            );
        }
        assert_eq!(
            files_in(&root, |n| n.starts_with("swarm-")),
            before,
            "{id}: nothing written"
        );
        return;
    }
    let core_steps = core.map(|core| field(core, "steps").as_array().unwrap());
    let mut token: Option<JsValue> = None;
    for (n, step) in steps.iter().enumerate() {
        let answer = match str_of(field(step, "op")) {
            "check" => {
                let eager = field(field(step, "options"), "eager") == &JsValue::Bool(true);
                let manifest = str_of(field(step, "manifest")).as_bytes().to_vec();
                let status = match step.get("status") {
                    Some(JsValue::Number(s)) => *s as u16,
                    None => 200,
                    Some(other) => panic!("{id}: status {}", short(other)),
                };
                let params = op_params(
                    "check",
                    &[
                        ("key", site.clone()),
                        ("url", url.clone()),
                        ("eager", JsValue::Bool(eager)),
                    ],
                );
                match manifest_call(main, params, Some((status, manifest))) {
                    Got::Value(answer) => Got::Value(match answer.get("token") {
                        Some(t) => {
                            token = Some(t.clone());
                            let mut answer = answer.clone();
                            answer.set("token", JsValue::string("(the consent token)"));
                            answer
                        }
                        None => answer,
                    }),
                    other => other,
                }
            }
            "decide" => manifest_call(
                main,
                op_params(
                    "decide",
                    &[
                        ("key", site.clone()),
                        ("token", token.clone().unwrap()),
                        ("outcome", field(step, "outcome").clone()),
                        ("live", JsValue::Bool(true)),
                    ],
                ),
                None,
            ),
            "useIndividual" => manifest_call(
                main,
                op_params(
                    "use-individual",
                    &[
                        ("origin", site.clone()),
                        ("capability", field(step, "capability").clone()),
                    ],
                ),
                None,
            ),
            "disconnect" => manifest_call(
                main,
                op_params("disconnect", &[("origin", site.clone())]),
                None,
            ),
            "get" => manifest_call(main, op_params("get", &[("origin", site.clone())]), None),
            other => panic!("{id}: manifest operation {other}"),
        };
        let want = match core_steps {
            Some(answers) => expected(&answers[n]),
            None => expected(step),
        };
        assert_answer(id, n, &answer, &want);
    }
    let side = core.unwrap_or(case);
    let want_grants: BTreeMap<String, Value> = match json_of(field(side, "grants_after")) {
        Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), reads(v))).collect(),
        other => panic!("{id}: grants {other}"),
    };
    assert_eq!(grants_read(main), want_grants, "{id}: grants");
    assert_eq!(
        files_in(&root, |n| n.starts_with("swarm-manifest-grants")
            || n == feeds::FILE_NAME),
        text_map(field(side, "files")),
        "{id}: files"
    );
}

// --- history ---------------------------------------------------------------------

fn sql_value(bind: &Bind) -> rusqlite::types::Value {
    match bind {
        Bind::Null => rusqlite::types::Value::Null,
        Bind::Integer(n) => rusqlite::types::Value::Integer(*n),
        Bind::Real(n) => rusqlite::types::Value::Real(*n),
        Bind::Text(t) => rusqlite::types::Value::Text(t.clone()),
    }
}

fn execute(conn: &rusqlite::Connection, statement: &Statement) -> usize {
    conn.execute(
        statement.sql,
        rusqlite::params_from_iter(statement.params.iter().map(sql_value)),
    )
    .unwrap()
}

fn query(conn: &rusqlite::Connection, statement: &Statement) -> Vec<Vec<Cell>> {
    let mut prepared = conn.prepare(statement.sql).unwrap();
    let columns = prepared.column_count();
    let rows = prepared
        .query_map(
            rusqlite::params_from_iter(statement.params.iter().map(sql_value)),
            |row| {
                (0..columns)
                    .map(|i| {
                        Ok(match row.get_ref(i)? {
                            rusqlite::types::ValueRef::Null => Cell::Null,
                            rusqlite::types::ValueRef::Integer(n) => Cell::Integer(n),
                            rusqlite::types::ValueRef::Real(n) => Cell::Real(n),
                            rusqlite::types::ValueRef::Text(t) => {
                                Cell::Text(String::from_utf8(t.to_vec()).unwrap())
                            }
                            rusqlite::types::ValueRef::Blob(b) => Cell::Blob(b.to_vec()),
                        })
                    })
                    .collect()
            },
        )
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn cell_value(cell: &Cell) -> JsValue {
    match cell {
        Cell::Null => JsValue::Null,
        Cell::Integer(n) => JsValue::Number(*n as f64),
        Cell::Real(n) => JsValue::Number(*n),
        Cell::Text(t) => JsValue::string(t.as_str()),
        Cell::Blob(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let mut out = JsValue::Object(Vec::new());
            out.set("blob", JsValue::string(hex.as_str()));
            out
        }
    }
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

/// The core's `publish-history.sqlite`, opened beside it (WAL): the publish
/// machines' statements the vectors seed, and the rows read back.
fn history_db(root: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(root.join(history::FILE_NAME)).unwrap();
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    conn
}

/// The publish machines' `addEntry`: the insert, the bound, the row back.
fn add_entry(
    conn: &rusqlite::Connection,
    entry: &JsValue,
    now_ms: u64,
) -> Result<JsValue, JsValue> {
    let thrown = |t: fc_swarm_provider::stores::Thrown| {
        let mut out = JsValue::Object(Vec::new());
        out.set("name", JsValue::string(t.name.as_str()));
        out.set("message", JsValue::string(t.message.as_str()));
        out
    };
    history::add_entry_checks(entry).map_err(thrown)?;
    execute(conn, &history::add_entry(entry, now_ms).map_err(thrown)?);
    let rowid = conn.last_insert_rowid();
    execute(conn, &history::trim(Some(rowid)));
    Ok(history::entry(&query(conn, &history::by_rowid(rowid))[0]).unwrap())
}

/// The publish machines' `updateEntry`.
fn update_entry(
    conn: &rusqlite::Connection,
    id: &JsValue,
    updates: &JsValue,
    now_ms: u64,
) -> Result<JsValue, JsValue> {
    let thrown = |t: fc_swarm_provider::stores::Thrown| {
        let mut out = JsValue::Object(Vec::new());
        out.set("name", JsValue::string(t.name.as_str()));
        out.set("message", JsValue::string(t.message.as_str()));
        out
    };
    history::update_entry_checks(updates).map_err(thrown)?;
    if execute(
        conn,
        &history::update_entry(id, updates, now_ms).map_err(thrown)?,
    ) == 0
    {
        return Ok(JsValue::Null);
    }
    Ok(history::entry(&query(conn, &history::by_id(id).map_err(thrown)?)[0]).unwrap())
}

fn history_op(main: &mut Main, op: &str, members: &[(&str, JsValue)]) -> Got {
    let mut own = OwnMain::new(|call, _| panic!("a history op called the node: {call:?}"));
    got(&main.play_own(&mut own, "swarm.history", &op_params(op, members), "chrome"))
}

fn play_history(main: &mut Main, case: &JsValue) {
    let id = str_of(field(case, "id"));
    let root = main.core.grant_root.clone();
    set_up(main, &Dir::new(), &JsValue::Object(Vec::new()), T0);
    if id == "history-10001-rows" {
        let op = &field(case, "ops").as_array().unwrap()[0];
        assert_eq!(field(op, "times"), &JsValue::Number(10001.0));
        let template = field(op, "args").as_array().unwrap()[0].clone();
        let conn = history_db(&root);
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..10001u32 {
            let mut entry = template.clone();
            entry.set("bytesSize", JsValue::Number(f64::from(i)));
            add_entry(&conn, &entry, T0).unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
        let Got::Value(JsValue::Array(ref entries)) = history_op(main, "list", &[]) else {
            panic!("{id}: list");
        };
        assert_eq!(entries.len(), 10_000);
        let ids: Vec<f64> = entries
            .iter()
            .map(|e| match e.get("id") {
                Some(JsValue::Number(n)) => *n,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            format!(
                "{{\"n\":{},\"first\":{},\"last\":{}}}",
                ids.len(),
                ids.iter().copied().fold(f64::INFINITY, f64::min),
                ids.iter().copied().fold(0.0, f64::max)
            ),
            field(field(case, "core"), "rows").stringify()
        );
        return;
    }
    if let Some(seed) = case.get("seeded") {
        let conn = history_db(&root);
        for step in seed.as_array().unwrap() {
            let step = step.as_array().unwrap();
            let arg = |i: usize| step.get(i).cloned().unwrap_or(JsValue::Undefined);
            match str_of(&step[0]) {
                "addEntry" => drop(add_entry(&conn, &arg(1), T0).unwrap()),
                "updateEntry" => drop(update_entry(&conn, &arg(1), &arg(2), T0).unwrap()),
                other => panic!("{id}: seeded {other}"),
            }
        }
        if let Some(blob) = case.get("blob") {
            let column = str_of(field(blob, "column"));
            let JsValue::Number(row) = field(blob, "id") else {
                panic!("{id}: a row id");
            };
            conn.execute(
                &format!("UPDATE publishes SET {column} = ?1 WHERE id = ?2"),
                rusqlite::params![hex_bytes(str_of(field(blob, "hex"))), *row as i64],
            )
            .unwrap();
        }
    }
    // The legacy file where the core's import reads it, then the history
    // opened again a second later, as at a start: the import, the sweep
    // and the bound.
    for (name, text) in text_map(case.get("user_data_before").unwrap_or(&JsValue::Null)) {
        std::fs::write(root.join(name), text).unwrap();
    }
    let now = T0 + 1000;
    main.world(json!({ "clock": now, "reload": true }));
    let conn = history_db(&root);
    let core = core_of(case);
    let core_ops = core.map(|core| field(core, "ops").as_array().unwrap());
    for (n, op) in field(case, "ops").as_array().unwrap().iter().enumerate() {
        let args = field(op, "args").as_array().unwrap().to_vec();
        let arg = |i: usize| args.get(i).cloned().unwrap_or(JsValue::Undefined);
        let want = core_ops.map_or(op, |answers| &answers[n]);
        let to_got = |r: Result<JsValue, JsValue>| match r {
            Ok(value) => Got::Value(value),
            Err(thrown) => Got::Thrown(thrown),
        };
        let answer = match str_of(field(op, "op")) {
            "addEntry" => to_got(add_entry(&conn, &arg(0), now)),
            "updateEntry" => to_got(update_entry(&conn, &arg(0), &arg(1), now)),
            "getEntries" => history_op(main, "list", &[]),
            "clearEntries" => history_op(main, "clear", &[]),
            "removeEntry" => history_op(main, "remove", &[("id", arg(0))]),
            other => panic!("{id}: history operation {other}"),
        };
        if let Some(refused) = want.get("refused") {
            assert_eq!(str_of(field(refused, "reason")), "blob", "{id} step {n}");
            let column = str_of(field(refused, "column"));
            let Got::Thrown(thrown) = &answer else {
                panic!("{id} step {n}: {answer:?}, want the BLOB refused");
            };
            assert_eq!(
                thrown.get("code").and_then(JsValue::as_str),
                Some("history_blob"),
                "{id} step {n}"
            );
            assert_eq!(
                thrown.get("message").and_then(JsValue::as_str),
                Some(format!("publish-history.sqlite holds a BLOB in column {column}").as_str()),
                "{id} step {n}"
            );
            continue;
        }
        assert_answer(id, n, &answer, &expected(want));
    }
    let rows: Vec<JsValue> = query(
        &conn,
        &Statement {
            sql: "SELECT * FROM publishes ORDER BY id",
            params: Vec::new(),
        },
    )
    .iter()
    .map(|row| {
        let mut out = JsValue::Object(Vec::new());
        for (column, cell) in history::COLUMNS.iter().zip(row) {
            out.set(*column, cell_value(cell));
        }
        out
    })
    .collect();
    assert_eq!(
        JsValue::Array(rows).stringify(),
        field(core.unwrap_or(case), "rows").stringify(),
        "{id}: rows"
    );
    // The legacy file as the import left it.
    if let Some(after) = case.get("user_data_after") {
        assert_eq!(
            files_in(&root, |n| n.starts_with("publish-history.json")),
            text_map(after),
            "{id}: user data"
        );
    }
}

// --- main's own node methods -------------------------------------------------------

/// `{ stamps: [<the usable batch a1a1…>] }`, stamps.select's
/// `usable/content-4096`.
fn usable_stamps() -> Vec<u8> {
    let text = logic::text_of("swarm.json");
    let index = Index::new(&text).unwrap();
    let case = get(get(index.root(), "stamps"), "select")
        .children()
        .find(|c| get(*c, "id").is_str("usable/content-4096"))
        .unwrap();
    get(case, "stamps")
        .stringify(KeyOrder::Property)
        .into_bytes()
}

fn json_reply(status: u16, headers: Vec<(&str, String)>, body: &str) -> Event {
    let mut headers: Vec<(String, String)> = headers
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    headers.insert(
        0,
        (
            "content-type".to_owned(),
            "application/json; charset=utf-8".to_owned(),
        ),
    );
    Event::Reply(Reply {
        status,
        status_text: logic::reason_phrase(status).to_owned(),
        headers,
        body: body.as_bytes().to_vec(),
    })
}

fn not_found() -> Event {
    json_reply(404, Vec::new(), r#"{"code":404,"message":"Not Found"}"#)
}

/// A node that answers every form main's own methods make honestly:
/// `/stamps` from the vectors, an upload with the SHA-256 of its body as
/// its reference and tag 101, a feed manifest, a SOC with its own address,
/// a tag, a batch; feed updates up to `head` exist.
fn honest(stamps: Vec<u8>, head: Option<u64>) -> impl FnMut(&NodeCall, &[u8]) -> Event {
    move |call: &NodeCall, body: &[u8]| match call.form {
        Form::Stamps => Event::Reply(Reply {
            status: 200,
            status_text: "OK".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: stamps.clone(),
        }),
        Form::BzzFile | Form::BzzTar => json_reply(
            201,
            vec![("swarm-tag", "101".to_owned())],
            &format!(r#"{{"reference":"{}"}}"#, logic::sha(body)),
        ),
        Form::FeedManifest => json_reply(
            201,
            Vec::new(),
            &format!(r#"{{"reference":"{}"}}"#, "e1".repeat(32)),
        ),
        Form::SocUp => {
            let segments: Vec<&str> = call.path.split('/').collect();
            let owner: [u8; 20] = logic::unhex(segments[2]).try_into().unwrap();
            let id: [u8; 32] = logic::unhex(segments[3]).try_into().unwrap();
            let address = fc_swarm::verify::soc_address(&id, &owner);
            json_reply(
                201,
                Vec::new(),
                &format!(r#"{{"reference":"{}"}}"#, logic::hex(&address)),
            )
        }
        Form::FeedHead => match head {
            Some(head) => Event::Reply(Reply {
                status: 200,
                status_text: "OK".to_owned(),
                headers: vec![
                    ("swarm-feed-index".to_owned(), format!("{head:016x}")),
                    (
                        "swarm-feed-index-next".to_owned(),
                        format!("{:016x}", head + 1),
                    ),
                ],
                body: Vec::new(),
            }),
            None => not_found(),
        },
        Form::Chunk => not_found(),
        Form::Tag => json_reply(
            200,
            Vec::new(),
            r#"{"uid":101,"address":"","split":10,"seen":0,"stored":10,"sent":5,"synced":10,"startedAt":"2026-01-01T00:00:00Z"}"#,
        ),
        Form::Stamp => json_reply(
            200,
            Vec::new(),
            r#"{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}"#,
        ),
        other => panic!("main's own methods make no {other:?} call"),
    }
}

fn value_of(got: Got) -> JsValue {
    match got {
        Got::Value(value) => value,
        other => panic!("a value: {other:?}"),
    }
}

/// The history's rows, through `swarm.history`.
fn history_rows(main: &mut Main) -> Vec<JsValue> {
    let JsValue::Array(ref rows) = value_of(history_op(main, "list", &[])) else {
        panic!("a list")
    };
    rows.clone()
}

/// The history's row of that name.
fn named<'r>(rows: &'r [JsValue], name: &str) -> &'r JsValue {
    rows.iter()
        .find(|row| row.get("name").and_then(JsValue::as_str) == Some(name))
        .unwrap_or_else(|| panic!("no row {name}"))
}

fn text_at(value: &JsValue, key: &str) -> String {
    str_of(field(value, key)).to_owned()
}

#[test]
fn main_s_own_node_methods_through_the_pipe() {
    let mut main = store_main();
    main.world(json!({ "reset": true, "clock": T0 }));
    let stamps = usable_stamps();
    let batch = "a1".repeat(32);

    // A picked file: its part streamed in, its body streamed out, its row.
    let mut own = OwnMain::new(honest(stamps.clone(), None));
    let picked = logic::content("picked", 200_000);
    own.parts.insert(0, picked.clone());
    let answer = main.play_own(
        &mut own,
        "swarm.publish",
        &json!({
            "kind": "file", "parts": [{ "bytes": 200_000, "part": 0 }], "name": "notes.txt",
            "pin": true, "deferred": true, "history": { "type": "file", "name": "notes.txt" },
        }),
        "shell",
    );
    let result = value_of(got(&answer));
    assert_eq!(own.parts_asked, [0]);
    let (upload, body) = own.calls.last().unwrap();
    assert_eq!(upload.form, Form::BzzFile);
    assert_eq!(body, &picked);
    assert_eq!(text_at(&result, "reference"), logic::sha(&picked));
    assert_eq!(text_at(&result, "batch"), batch);
    assert_eq!(field(&result, "tag_uid"), &JsValue::Number(101.0));
    assert_eq!(field(&result, "bytes"), &JsValue::Number(200_000.0));
    let rows = history_rows(&mut main);
    assert_eq!(rows.len(), 1);
    for (key, want) in [
        ("type", "file"),
        ("name", "notes.txt"),
        ("status", "completed"),
        ("origin", "freedom://publish"),
    ] {
        assert_eq!(text_at(&rows[0], key), want, "{key}");
    }
    assert_eq!(text_at(&rows[0], "reference"), logic::sha(&picked));

    // A collection: one part inline, one streamed, as a tar.
    let mut own = OwnMain::new(honest(stamps.clone(), None));
    let script = logic::content("script", 150_000);
    own.parts.insert(1, script.clone());
    let answer = main.play_own(
        &mut own,
        "swarm.publish",
        &json!({
            "kind": "collection",
            "parts": [
                { "path": "index.html", "bytes": 4, "base64": "PGgxPg==" },
                { "path": "assets/app.js", "bytes": 150_000, "part": 1 },
            ],
            "pin": true, "deferred": true, "history": { "type": "directory", "name": "site" },
        }),
        "shell",
    );
    let result = value_of(got(&answer));
    let (upload, tar) = own.calls.last().unwrap();
    assert_eq!(upload.form, Form::BzzTar);
    assert!(
        upload
            .headers
            .contains(&("swarm-index-document".to_owned(), "index.html".to_owned()))
    );
    assert!(tar.windows(script.len()).any(|w| w == script.as_slice()));
    assert_eq!(text_at(&result, "reference"), logic::sha(tar));
    let rows = history_rows(&mut main);
    assert_eq!(rows.len(), 2);
    let row = named(&rows, "site");
    assert_eq!(text_at(row, "type"), "directory");
    assert_eq!(text_at(row, "status"), "completed");
    assert_eq!(text_at(row, "reference"), logic::sha(tar));

    // A picked file whose read fails: describePickedPathError's text from
    // the part's error code, for the answer and the row.
    let mut own = OwnMain::new(honest(stamps.clone(), None));
    own.parts.insert(0, vec![9; 200_000]);
    own.abort_part = Some((0, "EACCES"));
    let answer = main.play_own(
        &mut own,
        "swarm.publish",
        &json!({
            "kind": "file", "parts": [{ "bytes": 200_000, "part": 0 }], "name": "/home/u/report.txt",
            "batch": batch, "pin": true, "deferred": true,
            "history": { "type": "file", "name": "report.txt" },
        }),
        "shell",
    );
    let Got::Thrown(thrown) = got(&answer) else {
        panic!("{answer}")
    };
    assert_eq!(
        text_at(&thrown, "message"),
        r#"Could not read "report.txt" (EACCES)"#
    );
    let rows = history_rows(&mut main);
    let row = named(&rows, "report.txt");
    assert_eq!(text_at(row, "status"), "failed");
    assert_eq!(
        text_at(row, "errorMessage"),
        r#"Could not read "report.txt" (EACCES)"#
    );

    // swarm.feed: create, an update at min_index, and a read.
    let text = logic::text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let keys = logic::keys(&index);
    let owner = fc_evm::address_of(&keys.bee);
    let topic = "77".repeat(32);
    let feed = |op: &str, extra: Value| {
        let mut params = json!({ "op": op, "key": { "kind": "bee_wallet" }, "topic": topic });
        for (k, v) in extra.as_object().unwrap() {
            params[k] = v.clone();
        }
        params
    };
    let mut own = OwnMain::new(honest(stamps.clone(), None));
    let created = value_of(got(&main.play_own(
        &mut own,
        "swarm.feed",
        &feed("create", json!({})),
        "shell",
    )));
    assert_eq!(text_at(&created, "owner"), fc_evm::checksum_address(&owner));
    assert_eq!(text_at(&created, "topic"), topic);
    assert_eq!(
        text_at(&created, "bzzUrl"),
        format!("bzz://{}", "e1".repeat(32))
    );
    assert_eq!(own.calls[0].0.form, Form::Stamps);
    assert_eq!(own.calls[1].0.form, Form::FeedManifest);

    let mut own = OwnMain::new(honest(stamps.clone(), None));
    let reference = "ef".repeat(32);
    let updated = value_of(got(&main.play_own(
        &mut own,
        "swarm.feed",
        &feed(
            "update",
            json!({ "reference": reference, "min_index": 5, "batch": batch }),
        ),
        "shell",
    )));
    assert_eq!(field(&updated, "index"), &JsValue::Number(5.0));
    let (soc, body) = own.calls.last().unwrap();
    let id = fc_swarm::verify::feed_update_id(&[0x77; 32], 5);
    assert_eq!(
        soc.path,
        format!("/soc/{}/{}", logic::hex(&owner), logic::hex(&id))
    );
    // span ‖ unix seconds ‖ reference, signed by the core's own vault.
    let mut payload = (T0 / 1000).to_be_bytes().to_vec();
    payload.extend_from_slice(&logic::unhex(&reference));
    let signed = fc_swarm::sign_soc(&keys.bee, &id, Some(40), &payload).unwrap();
    let signature = soc
        .query
        .iter()
        .find(|(k, _)| k == "sig")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(signature, logic::hex(&signed.signature));
    let mut wire = 40u64.to_le_bytes().to_vec();
    wire.extend_from_slice(&payload);
    assert_eq!(body, &wire);

    let mut own = OwnMain::new(honest(stamps.clone(), Some(5)));
    let read = value_of(got(&main.play_own(
        &mut own,
        "swarm.feed",
        &feed("read", json!({})),
        "shell",
    )));
    assert_eq!(read.stringify(), r#"{"exists":true,"index":5}"#);
    assert_eq!(own.calls.len(), 1);
    let mut own = OwnMain::new(honest(stamps.clone(), None));
    let read = value_of(got(&main.play_own(
        &mut own,
        "swarm.feed",
        &feed("read", json!({})),
        "shell",
    )));
    assert_eq!(read.stringify(), r#"{"exists":false}"#);
    assert_eq!(
        own.calls.iter().map(|(c, _)| c.form).collect::<Vec<_>>(),
        [Form::FeedHead, Form::Chunk]
    );

    // swarm.stamps and swarm.upload_status, the chrome's too.
    for caller in ["shell", "chrome"] {
        let mut own = OwnMain::new(honest(stamps.clone(), None));
        let all = value_of(got(&main.play_own(
            &mut own,
            "swarm.stamps",
            &json!({}),
            caller,
        )));
        let JsValue::Array(batches) = &all else {
            panic!("{}", short(&all))
        };
        assert_eq!(batches.len(), 1);
        assert_eq!(text_at(&batches[0], "batchID"), batch);
        let one = value_of(got(&main.play_own(
            &mut own,
            "swarm.stamps",
            &json!({ "id": batch }),
            caller,
        )));
        assert_eq!(text_at(&one, "batchID"), batch);
        assert!(matches!(field(&one, "batchTTL"), JsValue::Number(_)));
        let tag = value_of(got(&main.play_own(
            &mut own,
            "swarm.upload_status",
            &json!({ "tag_uid": 101 }),
            caller,
        )));
        assert_eq!(field(&tag, "tagUid"), &JsValue::Number(101.0));
        assert_eq!(
            own.calls.iter().map(|(c, _)| c.form).collect::<Vec<_>>(),
            [Form::Stamps, Form::Stamp, Form::Tag]
        );
    }
    // A node failure is what the service throws.
    let mut own = OwnMain::new(|_: &NodeCall, _: &[u8]| Event::Failed(Failed::Stopped));
    let thrown = got(&main.play_own(&mut own, "swarm.stamps", &json!({}), "shell"));
    assert_eq!(
        thrown,
        Got::Thrown(fc_json::parse(r#"{"message":"Swarm node is not ready"}"#).unwrap())
    );
}

// --- callers, admission and bounds --------------------------------------------------

/// The method table's callers (D5): a method a caller may not call is
/// `forbidden`, with nothing run; an op only main makes is refused to the
/// chrome (D7).
#[test]
fn callers_are_enforced() {
    let mut main = swarm_world::main();
    let refused = |main: &mut Main, method: &str, params: Value, caller: &str| {
        let id = main.own_request(method, &params, caller);
        let reply = main.core.response(id);
        assert_eq!(
            reply["error"]["code"], "forbidden",
            "{method} {caller}: {reply}"
        );
    };
    for method in ["swarm.publish", "swarm.feed", "swarm.manifest"] {
        refused(&mut main, method, json!({}), "chrome");
    }
    for method in [
        "swarm.publish",
        "swarm.feed",
        "swarm.stamps",
        "swarm.upload_status",
        "swarm.identities",
        "swarm.history",
        "swarm.manifest",
    ] {
        let id = main.id();
        let frame = format!(
            r#"{{"type":"request","id":{id},"method":"{method}","params":{{}},"context":{{"caller":"page","page":{}}}}}"#,
            swarm_world::page("https://a.example")
        );
        main.core
            .send_raw(&common::raw_frame(0x01, frame.as_bytes()));
        let reply = main.core.response(id);
        assert_eq!(
            reply["error"]["code"], "forbidden",
            "{method} page: {reply}"
        );
    }
    // The reverse: main's own and the chrome don't make a page's request.
    for caller in ["shell", "chrome"] {
        refused(&mut main, "swarm.request", json!({}), caller);
    }
    // Main's own op, from the chrome: forbidden; from main it runs.
    let params = op_params(
        "hasFeedGrant",
        &[("key", JsValue::string("https://a.example"))],
    );
    refused(&mut main, "swarm.identities", params.clone(), "chrome");
    let mut own = OwnMain::new(|call, _| panic!("{call:?}"));
    assert_eq!(
        got(&main.play_own(&mut own, "swarm.identities", &params, "shell")),
        Got::Value(JsValue::Bool(false))
    );
    // The chrome's own reads run.
    assert_eq!(
        got(&main.play_own(&mut own, "swarm.history", &op_params("list", &[]), "chrome")),
        Got::Value(JsValue::Array(Vec::new()))
    );
}

/// Admission's `busy` for main's own methods (D5, "Budgets"): with one
/// place and none to wait in, a second stamps read is the protocol error
/// `busy` while the first holds its place; the store ops that take no place
/// still answer. The stores not moved: `not_moved`.
#[test]
fn admission_is_busy_for_main() {
    let mut main = swarm_world::main_with(
        &["swarm"],
        &[
            ("FREEDOM_CORED_TEST_SWARM_RUNNING", "1"),
            ("FREEDOM_CORED_TEST_SWARM_WAITING", "0"),
        ],
    );
    let first = main.own_request("swarm.stamps", &json!({}), "shell");
    let call = loop {
        let message = main.recv();
        if message["type"] == "request" && message["method"] == "shell.swarm_api" {
            break message;
        }
    };
    let second = main.own_request("swarm.stamps", &json!({}), "chrome");
    let reply = main.core.response(second);
    assert_eq!(reply["error"]["code"], "busy", "{reply}");
    let publish = main.own_request(
        "swarm.publish",
        &json!({ "kind": "data", "parts": [{ "bytes": 5, "base64": "aGVsbG8=" }], "pin": true, "deferred": false }),
        "shell",
    );
    assert_eq!(main.core.response(publish)["error"]["code"], "busy");
    let history = main.own_request("swarm.history", &op_params("list", &[]), "chrome");
    assert!(main.core.response(history)["result"]["result_typed"].is_object());
    // The first's answer frees its place.
    main.answer(
        call["id"].as_u64().unwrap(),
        swarm_world::reply_json(&honest(usable_stamps(), None)(
            &swarm_world::node_call(&call["params"]),
            &[],
        )),
    );
    assert!(main.core.response(first)["result"]["result_typed"].is_object());
    main.settled();

    let mut unmoved = swarm_world::main_stores(&["swarm"], &[], &[]);
    let id = unmoved.own_request("swarm.history", &op_params("list", &[]), "chrome");
    let reply = unmoved.core.response(id);
    assert_eq!(reply["error"]["code"], "not_moved", "{reply}");
    assert_eq!(reply["error"]["data"]["store"], "swarm_stores");
}

const SITE: &str = "bzz://5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const MANIFEST: &str = r#"{"schema":"freedom-manifest/1","name":"Freedom Notes","description":"Notes on Swarm","capabilities":{"swarm":{"publish":{"why":"To publish your notes"}}}}"#;

fn check() -> Value {
    op_params(
        "check",
        &[
            ("key", JsValue::string(SITE)),
            ("url", JsValue::string(format!("{SITE}/index.html"))),
            ("eager", JsValue::Bool(true)),
        ],
    )
}

/// D6: `shell.swarm_manifest { for, url }` answered with the manifest, a
/// failure, or nothing until its 60 s bound (shortened by the test hook),
/// at which the core cancels it and the check reads it as unresolved.
#[test]
fn shell_swarm_manifest_answers_and_its_bound() {
    let mut main =
        swarm_world::main_with(&["swarm"], &[("FREEDOM_CORED_TEST_SWARM_IDLE_MS", "400")]);
    main.world(json!({ "reset": true, "clock": T0 }));
    // Answered: a consent.
    let mut own = OwnMain::new(|call, _| panic!("{call:?}"));
    own.manifest = Box::new(|_| Some(fetched(200, MANIFEST.as_bytes())));
    let answer = value_of(got(&main.play_own(
        &mut own,
        "swarm.manifest",
        &check(),
        "shell",
    )));
    assert_eq!(own.fetches, [format!("{SITE}/freedom-manifest.json")]);
    assert_eq!(text_at(&answer, "kind"), "consent");
    // A failure main reports: unresolved, with its backoff (a site with
    // no record yet: legacy).
    no_manifests(&mut main);
    let mut own = OwnMain::new(|call, _| panic!("{call:?}"));
    own.manifest = Box::new(|_| Some(json!({ "failed": "unreachable" })));
    let answer = value_of(got(&main.play_own(
        &mut own,
        "swarm.manifest",
        &check(),
        "shell",
    )));
    assert_eq!(text_at(&answer, "reason"), "unresolved");
    // No answer: the core cancels the fetch at its bound, the check reads
    // it as unresolved, and main's `cancelled` lets its charge go.
    no_manifests(&mut main);
    let mut own = OwnMain::new(|call, _| panic!("{call:?}"));
    own.manifest = Box::new(|_| None);
    let started = std::time::Instant::now();
    let answer = value_of(got(&main.play_own(
        &mut own,
        "swarm.manifest",
        &check(),
        "shell",
    )));
    assert!(started.elapsed() >= std::time::Duration::from_millis(400));
    assert_eq!(own.cancels, 1);
    assert_eq!(text_at(&answer, "reason"), "unresolved");
}

/// The manifest store empty again, as at a start with no file.
fn no_manifests(main: &mut Main) {
    let root = main.core.grant_root.clone();
    for (name, _) in files_in(&root, |n| n.starts_with("swarm-manifest-grants")) {
        std::fs::remove_file(root.join(name)).unwrap();
    }
    main.world(json!({ "reload": true }));
}

/// A decision's projections write the Swarm grants (D2) and send
/// `approval.changed` after the answer; the file is the core's.
#[test]
fn a_projection_sends_approval_changed_after_its_answer() {
    let mut main = swarm_world::main();
    main.world(json!({ "reset": true, "clock": T0 }));
    let mut own = OwnMain::new(|call, _| panic!("{call:?}"));
    own.manifest = Box::new(|_| Some(fetched(200, MANIFEST.as_bytes())));
    let answer = value_of(got(&main.play_own(
        &mut own,
        "swarm.manifest",
        &check(),
        "shell",
    )));
    let token = field(&answer, "token").clone();
    main.core.events.clear();
    let decide = op_params(
        "decide",
        &[
            ("key", JsValue::string(SITE)),
            ("token", token),
            ("outcome", JsValue::string("allow")),
            ("live", JsValue::Bool(true)),
        ],
    );
    let id = main.own_request("swarm.manifest", &decide, "shell");
    let reply = main.core.response(id);
    assert_eq!(
        got(&reply),
        Got::Value(fc_json::parse(r#"{"allowed":true,"mode":"allow"}"#).unwrap())
    );
    // Nothing before the answer; the connection and the rule after it.
    assert!(main.core.events.is_empty(), "{:?}", main.core.events);
    let mut changed = Vec::new();
    while changed.len() < 2 {
        let message = main.core.recv();
        assert_eq!(message["type"], "event", "{message}");
        changed.push(message);
    }
    for event in &changed {
        assert_eq!(event["event"], "approval.changed", "{event}");
        assert_eq!(event["data"], json!({ "store": "swarm", "key": SITE }));
    }
    let file =
        std::fs::read_to_string(main.core.grant_root.join("swarm-permissions.json")).unwrap();
    let grants: Value = serde_json::from_str(&file).unwrap();
    assert_eq!(grants[SITE]["autoApprove"]["publish"], true);
    let read = grants_read(&mut main);
    assert_eq!(read[SITE]["autoApprove"]["publish"], true);
}
