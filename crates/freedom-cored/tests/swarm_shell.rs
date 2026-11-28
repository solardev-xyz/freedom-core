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
//!   file the core left; `addEntry` and `updateEntry` go through main's
//!   `swarm.history` `add` and `update`, and the rows a case seeds before
//!   the history's reopen are run on the core's database directly. Each
//!   case: every answer (the case's `core` where a deviation changes it),
//!   the files the core left on disk, the Swarm grants as `approval.grants`
//!   reads them, the history's rows.
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
//! - **`swarm.history`'s `add` and `update`** (the 2026-11-28 amendment's
//!   K1): main's alone (the chrome and a page `forbidden`), their params
//!   read strictly, `add`'s bound keeping the row it inserted with the
//!   clock set back, and a write that fails thrown with the history's text.
//! - **D17:** a user's Swarm grant change, which the event loop writes,
//!   detaches what a manifest managed of it in the swarm thread's manifest
//!   store, after a check in flight and before main's next op of the site;
//!   a manifest's own projections detach nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod swarm_world;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fc_json::index::{Index, KeyOrder, Value as V};
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
    history_op_from(main, op, members, "chrome")
}

fn history_op_from(main: &mut Main, op: &str, members: &[(&str, JsValue)], caller: &str) -> Got {
    let mut own = OwnMain::new(|call, _| panic!("a history op called the node: {call:?}"));
    got(&main.play_own(&mut own, "swarm.history", &op_params(op, members), caller))
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
        let answer = match str_of(field(op, "op")) {
            "addEntry" => history_op_from(main, "add", &[("entry", arg(0))], "shell"),
            "updateEntry" => history_op_from(
                main,
                "update",
                &[("id", arg(0)), ("updates", arg(1))],
                "shell",
            ),
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
        let mut params = json!({
            "op": op, "key": { "kind": "bee_wallet" }, "owner": logic::hex(&owner), "topic": topic,
        });
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

/// The test mnemonic's Bee wallet (keys.json's `abandon-12`, the core's
/// vault in these tests) in `<o>`'s form: the `owner` main names for
/// `swarm.feed` (K2).
fn bee_owner() -> String {
    bee_owner_of("abandon-12")
}

/// A keys.json vector's Bee wallet in `<o>`'s form.
fn bee_owner_of(id: &str) -> String {
    let text = logic::text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let vector = get(index.root(), "vectors")
        .children()
        .find(|v| get(*v, "id").is_str(id))
        .unwrap();
    let address = logic::string(get(get(vector, "beeWallet"), "address"));
    address.strip_prefix("0x").unwrap().to_ascii_lowercase()
}

/// The other mnemonic the vault is replaced with, as `vault.import` takes
/// it (keys.json's `legal-12`, as the last update's owner shows).
const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// `swarm.feed` takes the Bee wallet's owner main showed (K2), through the
/// binary:
/// - a malformed `owner` (absent, `null`, a number, `0x`, upper or mixed
///   case, 39 or 41 digits, not hex) is `invalid_argument`, with nothing
///   asked of main or the vault;
/// - an owner the vault doesn't hold is refused for each op, with a batch
///   or none, before any node call: `owner_changed` and its text;
/// - the vault replaced (`vault.import` with `overwrite`, another mnemonic)
///   after an update's owner check, while its lookup is out: the vault
///   signs under the new key, and the update refuses that signature before
///   its upload (`createSwarmSigner`'s text), nothing uploaded; the next
///   request naming the old owner is refused `owner_changed`, and one
///   naming the new owner goes on.
#[test]
fn swarm_feed_takes_the_owner_main_showed() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    let mut main = store_main();
    main.world(json!({ "reset": true, "clock": T0 }));
    let owner = bee_owner();
    let topic = "77".repeat(32);
    let reference = "ef".repeat(32);
    let batch = "a1".repeat(32);
    let params = |op: &str, owner: Option<Value>, extra: Value| {
        let mut params = json!({ "op": op, "key": { "kind": "bee_wallet" }, "topic": topic });
        if let Some(owner) = owner {
            params["owner"] = owner;
        }
        for (k, v) in extra.as_object().unwrap() {
            params[k] = v.clone();
        }
        params
    };
    let refused_text = r#"{"message":"The Bee wallet this feed request names is no longer the vault's","code":"owner_changed"}"#;

    // Malformed owners: refused as the params are read.
    let checksummed = fc_evm::checksum_address(&logic::unhex(&owner).try_into().unwrap());
    for bad in [
        None,
        Some(json!(null)),
        Some(json!(7)),
        Some(json!(checksummed.clone())),
        Some(json!(format!("0x{owner}"))),
        Some(json!(checksummed[2..].to_owned())),
        Some(json!(owner.to_uppercase())),
        Some(json!(owner[..39].to_owned())),
        Some(json!(format!("{owner}0"))),
        Some(json!(format!("{}zz", &owner[..38]))),
    ] {
        for op in ["create", "update", "read"] {
            let extra = if op == "update" {
                json!({ "reference": reference })
            } else {
                json!({})
            };
            let sent = params(op, bad.clone(), extra);
            let id = main.own_request("swarm.feed", &sent, "shell");
            let reply = main.core.response(id);
            assert_eq!(
                reply["error"]["code"], "invalid_argument",
                "{sent}: {reply}"
            );
            assert!(
                reply["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("params.owner: "),
                "{sent}: {reply}"
            );
        }
    }
    main.settled();

    // Another vault's Bee wallet: each op refused before any node call.
    let other = bee_owner_of("abandon-24");
    assert_ne!(other, owner);
    for (op, extra) in [
        ("create", json!({})),
        ("create", json!({ "batch": batch })),
        ("update", json!({ "reference": reference })),
        (
            "update",
            json!({ "reference": reference, "batch": batch, "min_index": 3 }),
        ),
        ("read", json!({})),
    ] {
        let mut own = OwnMain::new(|call: &NodeCall, _: &[u8]| panic!("a node call {call:?}"));
        let sent = params(op, Some(json!(other)), extra);
        let thrown = got(&main.play_own(&mut own, "swarm.feed", &sent, "shell"));
        assert_eq!(
            thrown,
            Got::Thrown(fc_json::parse(refused_text).unwrap()),
            "{sent}"
        );
        assert!(own.calls.is_empty(), "{sent}");
    }

    // The vault replaced while an update's lookup is out.
    let update = params(
        "update",
        Some(json!(owner)),
        json!({ "reference": reference, "batch": batch }),
    );
    let request = main.own_request("swarm.feed", &update, "shell");
    let call = main.recv();
    assert_eq!(call["method"], "shell.swarm_api", "{call}");
    assert_eq!(call["params"]["form"], "feed_head", "{call}");
    assert!(
        call["params"]["path"].as_str().unwrap().contains(&owner),
        "{call}"
    );
    let id = main.id();
    let imported = main.core.call(
        id,
        "vault.import",
        json!({
            "password_b64": STANDARD.encode(swarm_world::PASSWORD),
            "mnemonic_b64": STANDARD.encode(LEGAL),
            "overwrite": true,
        }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    main.answer(
        call["id"].as_u64().unwrap(),
        json!({
            "status": 200, "status_text": "OK",
            "headers": [["swarm-feed-index", "0000000000000002"], ["swarm-feed-index-next", "0000000000000003"]],
            "body_base64": "",
        }),
    );
    // No soc_up: the answer is next.
    let answer = main.recv();
    assert_eq!(answer["type"], "response", "{answer}");
    assert_eq!(answer["id"], request, "{answer}");
    assert_eq!(
        got(&answer),
        Got::Thrown(
            fc_json::parse(
                r#"{"message":"The identity core returned a chunk signature that does not match"}"#
            )
            .unwrap()
        )
    );
    main.settled();
    // The old owner is refused now; the new one's update goes on.
    let mut own = OwnMain::new(|call: &NodeCall, _: &[u8]| panic!("a node call {call:?}"));
    let thrown = got(&main.play_own(&mut own, "swarm.feed", &update, "shell"));
    assert_eq!(thrown, Got::Thrown(fc_json::parse(refused_text).unwrap()));
    let legal = bee_owner_of("legal-12");
    let mut own = OwnMain::new(honest(usable_stamps(), None));
    let updated = value_of(got(&main.play_own(
        &mut own,
        "swarm.feed",
        &params(
            "update",
            Some(json!(legal)),
            json!({ "reference": reference, "batch": batch }),
        ),
        "shell",
    )));
    assert_eq!(field(&updated, "index"), &JsValue::Number(0.0));
    let (soc, _) = own.calls.last().unwrap();
    assert!(
        soc.path.starts_with(&format!("/soc/{legal}/")),
        "{}",
        soc.path
    );
}

/// `swarm.publish`'s history failures carry a code (core PR K2), through
/// the binary, each with the history's fixed text:
/// - the insert failing (`swarm_history:write`): `history_insert`, no node
///   call, no row;
/// - the bound's trim failing after the insert (`swarm_history:batch`):
///   `history_insert`, no node call (the row's `failed` update and its
///   retry fail too, so the row stays `uploading` for the next open's
///   sweep);
/// - the `completed` update failing (`swarm_history:write` turned on while
///   the upload is out): `history_update`, the upload made;
/// - an upload that fails, then its `failed` update: `history_update`.
///
/// The hooks off, the same publish answers its result, the row
/// `completed`.
#[test]
fn swarm_publish_s_history_failures_carry_their_code() {
    let dir = tempfile::tempdir().unwrap();
    let hooks = dir.path().join("fail");
    let mut main = swarm_world::main_with(
        &["swarm"],
        &[(
            "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL",
            hooks.to_str().unwrap(),
        )],
    );
    main.world(json!({ "reset": true, "clock": T0 }));
    let publish = json!({
        "kind": "data", "parts": [{ "bytes": 5, "base64": "aGVsbG8=" }], "batch": "a1".repeat(32),
        "pin": true, "deferred": false, "history": { "type": "data", "name": "Text" },
    });
    let failed = |code: &str| {
        Got::Thrown(
            fc_json::parse(&format!(
                r#"{{"message":"The publish history could not be read or written","code":"{code}"}}"#
            ))
            .unwrap(),
        )
    };
    let statuses = |main: &mut Main| -> Vec<String> {
        let mut statuses: Vec<String> = history_rows(main)
            .iter()
            .map(|row| text_at(row, "status"))
            .collect();
        statuses.sort();
        statuses
    };
    let no_call = || OwnMain::new(|call: &NodeCall, _: &[u8]| panic!("a node call {call:?}"));

    // The insert.
    std::fs::write(&hooks, "swarm_history:write\n").unwrap();
    let answer = main.play_own(&mut no_call(), "swarm.publish", &publish, "shell");
    assert_eq!(got(&answer), failed("history_insert"));
    std::fs::remove_file(&hooks).unwrap();
    assert!(statuses(&mut main).is_empty(), "no row");

    // The bound's trim after it.
    std::fs::write(&hooks, "swarm_history:batch\n").unwrap();
    let answer = main.play_own(&mut no_call(), "swarm.publish", &publish, "shell");
    assert_eq!(got(&answer), failed("history_insert"));
    std::fs::remove_file(&hooks).unwrap();
    assert_eq!(statuses(&mut main), ["uploading"]);

    // A later update: the completed one, then a failure's own.
    let reference = "e1".repeat(32);
    for (status, body) in [
        (201, format!(r#"{{"reference":"{reference}"}}"#)),
        (500, r#"{"code":500,"message":"boom"}"#.to_owned()),
    ] {
        let request = main.own_request("swarm.publish", &publish, "shell");
        let call = main.recv();
        assert_eq!(call["method"], "shell.swarm_api", "{call}");
        assert_eq!(call["params"]["form"], "bzz_file", "{call}");
        std::fs::write(&hooks, "swarm_history:write\n").unwrap();
        main.answer(
            call["id"].as_u64().unwrap(),
            json!({
                "status": status,
                "status_text": if status == 201 { "Created" } else { "Internal Server Error" },
                "headers": [["content-type", "application/json"], ["swarm-tag", "101"]],
                "body_base64": fc_swarm_provider::value::encode_base64(body.as_bytes()),
            }),
        );
        let answer = main.core.response(request);
        assert_eq!(got(&answer), failed("history_update"), "{status}");
        std::fs::remove_file(&hooks).unwrap();
        main.settled();
    }
    assert_eq!(statuses(&mut main), ["uploading", "uploading", "uploading"]);

    // The hooks off: the result, the row completed.
    let mut own = OwnMain::new(honest(usable_stamps(), None));
    let result = value_of(got(&main.play_own(
        &mut own,
        "swarm.publish",
        &publish,
        "shell",
    )));
    assert_eq!(field(&result, "tag_uid"), &JsValue::Number(101.0));
    assert_eq!(
        statuses(&mut main),
        ["completed", "uploading", "uploading", "uploading"]
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

/// `swarm.history`'s `add` and `update` (the 2026-11-28 amendment's K1),
/// through the binary: main's alone (the chrome's call `forbidden` by the
/// op's name alone, a malformed member too, a page's by the method table,
/// nothing written); params read
/// strictly (an unknown member, an untyped one, bytes or a BigInt:
/// `invalid_argument`); main's rows written and read back; `add`'s bound
/// (deviation `history-bound`) trimming the oldest finished row and keeping
/// the one it inserted, the clock set back so that it is the oldest; and a
/// write that fails (the test hooks' `swarm_history:write`) thrown with the
/// history's fixed text, nothing written.
#[test]
fn main_s_history_ops_through_the_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let hooks = dir.path().join("fail");
    let mut main = swarm_world::main_with(
        &["swarm"],
        &[(
            "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL",
            hooks.to_str().unwrap(),
        )],
    );
    let root = main.core.grant_root.clone();
    set_up(&mut main, &Dir::new(), &JsValue::Object(Vec::new()), T0);
    let parse = |text: &str| fc_json::parse(text).unwrap();
    let entry = parse(
        r#"{"type":"directory","name":"site","status":"uploading","origin":"freedom://agent","bytesSize":4096}"#,
    );
    let add = op_params("add", &[("entry", entry.clone())]);
    let update = op_params(
        "update",
        &[
            ("id", JsValue::Number(1.0)),
            ("updates", parse(r#"{"status":"completed"}"#)),
        ],
    );
    for (op, params) in [("add", &add), ("update", &update)] {
        let id = main.own_request("swarm.history", params, "chrome");
        let reply = main.core.response(id);
        assert_eq!(reply["error"]["code"], "forbidden", "{op}: {reply}");
        assert_eq!(
            reply["error"]["message"],
            format!("{op} is main's own op"),
            "{op}"
        );
        let id = main.id();
        let frame = format!(
            r#"{{"type":"request","id":{id},"method":"swarm.history","params":{params},"context":{{"caller":"page","page":{}}}}}"#,
            swarm_world::page("https://a.example")
        );
        main.core
            .send_raw(&common::raw_frame(0x01, frame.as_bytes()));
        let reply = main.core.response(id);
        assert_eq!(reply["error"]["code"], "forbidden", "{op} page: {reply}");
    }
    // Refused on the op's name alone: a malformed member, which main's call
    // gets `invalid_argument` for (below), is still `forbidden` from the
    // chrome.
    for params in [
        json!({ "op": "add", "entry": {} }),
        json!({ "entry": "raw", "op": "add" }),
        json!({ "op": "add", "entry": { "bigint": "x" } }),
        json!({ "op": "update", "id": 1, "updates": {} }),
        json!({ "updates": { "string": 5 }, "op": "update" }),
    ] {
        let id = main.own_request("swarm.history", &params, "chrome");
        let reply = main.core.response(id);
        assert_eq!(reply["error"]["code"], "forbidden", "{params}: {reply}");
        let id = main.own_request("swarm.history", &params, "shell");
        let reply = main.core.response(id);
        assert_eq!(
            reply["error"]["code"], "invalid_argument",
            "{params}: {reply}"
        );
    }
    for params in [
        json!({ "op": "add", "entry": { "object": [] }, "extra": { "null": true } }),
        json!({ "op": "update", "id": { "number": "1" }, "entry": { "object": [] } }),
        json!({ "op": "add", "entry": {} }),
        json!({ "op": "update", "id": 1 }),
        json!({ "op": "add", "entry": { "object": [["name", { "bytes": 1, "kind": "Buffer", "base64": "YQ==" }]] } }),
        json!({ "op": "update", "id": { "bigint": "1" } }),
    ] {
        let id = main.own_request("swarm.history", &params, "shell");
        let reply = main.core.response(id);
        assert_eq!(
            reply["error"]["code"], "invalid_argument",
            "{params}: {reply}"
        );
    }
    assert_eq!(stored_rows(&root).stringify(), "[]", "nothing written");
    // Main's rows: the agent's before its upload, then its outcome.
    let iso = |text: &str| Some(JsValue::string(text));
    let Got::Value(row) = history_op_from(&mut main, "add", &[("entry", entry.clone())], "shell")
    else {
        panic!("add");
    };
    assert_eq!(row.get("id"), Some(&JsValue::Number(1.0)));
    assert_eq!(row.get("origin"), Some(&JsValue::string("freedom://agent")));
    assert_eq!(
        row.get("timestamp"),
        iso("2026-01-01T00:00:00.123Z").as_ref()
    );
    assert_eq!(row.get("completedAt"), Some(&JsValue::Null));
    main.world(json!({ "clock": T0 + 5000 }));
    let Got::Value(row) = got(&main.play_own(
        &mut OwnMain::new(|call, _| panic!("{call:?}")),
        "swarm.history",
        &update,
        "shell",
    )) else {
        panic!("update");
    };
    assert_eq!(row.get("status"), Some(&JsValue::string("completed")));
    assert_eq!(
        row.get("completedAt"),
        iso("2026-01-01T00:00:05.123Z").as_ref()
    );
    assert_eq!(
        history_op_from(
            &mut main,
            "update",
            &[
                ("id", JsValue::Number(2.0)),
                ("updates", parse(r#"{"status":"failed"}"#)),
            ],
            "shell",
        ),
        Got::Value(JsValue::Null),
        "a missing row"
    );
    // The bound: 10,000 rows, the second half finished, then an insert with
    // the clock set back.
    set_up(&mut main, &Dir::new(), &JsValue::Object(Vec::new()), T0);
    {
        let conn = history_db(&root);
        conn.execute_batch("BEGIN").unwrap();
        for i in 1..=history::MAX_ROWS as i64 {
            let status = if i > 5000 { "completed" } else { "uploading" };
            conn.execute(
                "INSERT INTO publishes (type, status, started_at) VALUES ('data', ?1, ?2)",
                rusqlite::params![status, T0 as i64 + i],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
    }
    let early = T0 - 1_000_000;
    main.world(json!({ "clock": early }));
    let Got::Value(row) = history_op_from(&mut main, "add", &[("entry", entry.clone())], "shell")
    else {
        panic!("add at the bound");
    };
    assert_eq!(row.get("id"), Some(&JsValue::Number(10_001.0)));
    assert_eq!(
        row.get("timestamp"),
        iso("2025-12-31T23:43:20.123Z").as_ref()
    );
    let ids = || -> Vec<i64> {
        let conn = history_db(&root);
        let mut statement = conn
            .prepare("SELECT id FROM publishes ORDER BY id")
            .unwrap();
        statement
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let kept: Vec<i64> = (1..=10_001).filter(|i| *i != 5001).collect();
    assert_eq!(
        ids(),
        kept,
        "the oldest finished row trimmed, the new one kept"
    );
    // A write that fails: the history's text, nothing written.
    std::fs::write(&hooks, "swarm_history:write\n").unwrap();
    for (op, params) in [("add", &add), ("update", &update)] {
        let Got::Thrown(thrown) = got(&main.play_own(
            &mut OwnMain::new(|call, _| panic!("{call:?}")),
            "swarm.history",
            params,
            "shell",
        )) else {
            panic!("{op}: thrown");
        };
        assert_eq!(thrown.get("name"), Some(&JsValue::string("Error")), "{op}");
        assert_eq!(
            thrown.get("message"),
            Some(&JsValue::string(
                "The publish history could not be read or written"
            )),
            "{op}"
        );
        assert_eq!(thrown.get("code"), None, "{op}");
    }
    std::fs::remove_file(&hooks).unwrap();
    assert_eq!(ids(), kept, "nothing written");
    let Got::Value(JsValue::Array(ref rows)) = history_op(&mut main, "list", &[]) else {
        panic!("list");
    };
    assert_eq!(rows.len(), history::MAX_ROWS);
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
    own.manifest = Box::new(|_| Some(json!({ "failed": true })));
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
    // The thread's clock floors to whole milliseconds: the bound can pass
    // up to 1 ms early by this test's clock.
    assert!(
        started.elapsed() + std::time::Duration::from_millis(2)
            >= std::time::Duration::from_millis(400)
    );
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

// --- D17: a user's Swarm grant change detaches ----------------------------------

/// `SITE`'s record: a manifest that manages the connection and the publish
/// rule, the publish capability acknowledged.
const MANAGED: &str = r#"{"managed":{"connection":["publish"],"autoApprove.publish":["publish"]},"acknowledged":{"publish":{"decision":"managed","source":"sheet","decidedAt":1}},"revision":1}"#;
const OTHER: &str = "https://other.example";
const OTHER_RECORD: &str = r#"{"managed":{"connection":["feeds"],"autoApprove.publish":["feeds"]},"acknowledged":{"feeds":{"decision":"managed","source":"sheet","decidedAt":1}},"revision":5}"#;
/// A connected site with no record.
const LEGACY: &str = "https://legacy.example";

/// The Swarm grants (the file's form): each site connected with its
/// publish rule.
fn connected(sites: &[&str]) -> JsValue {
    let mut grants = JsValue::Object(Vec::new());
    for site in sites {
        let grant = format!(
            r#"{{"origin":"{site}","connectedAt":1,"lastUsed":1,"autoApprove":{{"publish":true,"feeds":false,"signing":false,"messaging":false}}}}"#
        );
        grants.set(*site, fc_json::parse(&grant).unwrap());
    }
    grants
}

/// `SITE` on the Bee wallet, with its feed grant.
fn site_feeds() -> String {
    format!(
        r#"{{"version":2,"nextPublisherKeyIndex":0,"origins":{{"{SITE}":{{"activeIdentityId":"bee-wallet","identities":{{"bee-wallet":{{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee","createdAt":1,"lastUsedAt":null}}}},"feedGranted":true,"grantedAt":1,"feeds":{{}}}}}}}}"#
    )
}

/// `swarm.manifest get` of `site`: its record, or null.
fn record_of(main: &mut Main, site: &str) -> JsValue {
    let mut own = OwnMain::new(|call, _| panic!("{call:?}"));
    let params = op_params("get", &[("origin", JsValue::string(site))]);
    value_of(got(&main.play_own(
        &mut own,
        "swarm.manifest",
        &params,
        "shell",
    )))
}

/// An approval method from `context`'s caller: its result.
fn approval(main: &mut Main, method: &str, params: Value, context: Value) -> Value {
    let id = main.id();
    main.core.send(&json!({
        "type": "request", "id": id, "method": method, "params": params, "context": context,
    }));
    let reply = main.core.response(id);
    assert!(reply["result"].is_object(), "{method}: {reply}");
    reply["result"].clone()
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

/// `approval.changed` for `site`, once: the event loop's own for its write,
/// and nothing from the swarm thread's detach.
fn told_once(main: &mut Main, site: &str) {
    let events = main.core.events();
    assert_eq!(
        events,
        [
            json!({ "type": "event", "event": "approval.changed", "data": { "store": "swarm", "key": site } })
        ]
    );
}

/// D17 through the pipe: the chrome's narrowing and a page's own rule,
/// which the event loop writes, detach that projection from the site's
/// record in the swarm thread's manifest store, saved before the next op
/// of main's reads it; the record's other projections stay managed, another
/// site's record and a site with none change nothing, and main hears only
/// the loop's own `approval.changed`. A connection the user revoked
/// disconnects: the record goes, and the site's feed grant with it.
#[test]
fn a_users_grant_change_detaches_through_the_pipe() {
    let mut main = swarm_world::main();
    let root = main.core.grant_root.clone();
    let mut dir = Dir::new();
    dir.insert(
        manifests::FILE_NAME.to_owned(),
        format!(r#"{{"version":1,"records":{{"{SITE}":{MANAGED},"{OTHER}":{OTHER_RECORD}}}}}"#),
    );
    dir.insert(feeds::FILE_NAME.to_owned(), site_feeds());
    set_up(&mut main, &dir, &connected(&[SITE, OTHER, LEGACY]), T0);
    let swarm = |key: &str, what: Value| json!({ "store": "swarm", "key": key, "what": what });
    main.core.events.clear();
    // The chrome turns the publish rule off.
    let revoked = approval(
        &mut main,
        "approval.revoke",
        swarm(SITE, json!({ "flag": "publish" })),
        chrome(),
    );
    assert_eq!(revoked, json!({ "revoked": true }));
    assert_eq!(
        record_of(&mut main, SITE).stringify(),
        r#"{"managed":{"connection":["publish"]},"acknowledged":{"publish":{"decision":"managed","source":"sheet","decidedAt":1}},"revision":2,"detached":{"autoApprove.publish":true}}"#
    );
    told_once(&mut main, SITE);
    let file = std::fs::read_to_string(root.join(manifests::FILE_NAME)).unwrap();
    assert!(file.contains(r#""autoApprove.publish": true"#), "{file}");
    // The page's own "always allow" for feeds, which the manifest doesn't
    // manage: marked detached all the same, as the reference does.
    let page = json!({ "caller": "page", "page": swarm_world::page(SITE) });
    let grant = json!({ "store": "swarm", "change": { "op": "flag", "flag": "feeds" } });
    approval(&mut main, "approval.grant", grant, page);
    let record = record_of(&mut main, SITE);
    assert_eq!(
        field(&record, "detached").stringify(),
        r#"{"autoApprove.publish":true,"autoApprove.feeds":true}"#
    );
    assert_eq!(field(&record, "revision"), &JsValue::Number(3.0));
    assert_eq!(
        field(&record, "managed").stringify(),
        r#"{"connection":["publish"]}"#
    );
    told_once(&mut main, SITE);
    // A site with no record: the file stays as it was.
    let before = files_in(&root, |n| n.starts_with("swarm-manifest-grants"));
    approval(
        &mut main,
        "approval.revoke",
        swarm(LEGACY, json!({ "flag": "publish" })),
        chrome(),
    );
    assert_eq!(record_of(&mut main, LEGACY), JsValue::Null);
    assert_eq!(
        files_in(&root, |n| n.starts_with("swarm-manifest-grants")),
        before
    );
    told_once(&mut main, LEGACY);
    // The connection: the record goes, and the feed grant with it.
    approval(
        &mut main,
        "approval.revoke",
        swarm(SITE, json!("grant")),
        chrome(),
    );
    assert_eq!(record_of(&mut main, SITE), JsValue::Null);
    assert!(!feeds_on_disk(&root).has_feed_grant(&JsString::from(SITE)));
    assert!(!grants_read(&mut main).contains_key(SITE));
    told_once(&mut main, SITE);
    // Another site's record, untouched throughout.
    assert_eq!(record_of(&mut main, OTHER).stringify(), OTHER_RECORD);
    main.settled();
}

/// D17 and a failed narrowing: the chrome's revoke whose rename fails
/// stands in memory, unsaved (`storage`, `applied: true`), and still
/// detaches. The detach's disconnect finds the connection already gone in
/// memory, and writes the file the loop left behind before the record's
/// removal commits, so a restart reads the site disconnected, its record
/// and its feed grant gone.
#[test]
fn a_failed_revoke_detaches_and_stays_after_a_restart() {
    let hooks = tempfile::tempdir().unwrap();
    let hook = hooks.path().join("grant-write-fail");
    std::fs::write(&hook, "").unwrap();
    let hook_env = hook.to_string_lossy().into_owned();
    let env = [("FREEDOM_CORED_TEST_GRANT_WRITE_FAIL", hook_env.as_str())];
    let mut main = swarm_world::main_with(&["swarm"], &env);
    let root = main.core.grant_root.clone();
    let grants = connected(&[SITE]);
    let mut dir = Dir::new();
    dir.insert(
        manifests::FILE_NAME.to_owned(),
        format!(r#"{{"version":1,"records":{{"{SITE}":{MANAGED}}}}}"#),
    );
    dir.insert(feeds::FILE_NAME.to_owned(), site_feeds());
    dir.insert("swarm-permissions.json".to_owned(), grants.stringify());
    set_up(&mut main, &dir, &grants, T0);
    // The loop's write alone: the swarm thread's after it succeeds.
    std::fs::write(&hook, "swarm:rename-once").unwrap();
    let id = main.id();
    main.core.send(&json!({
        "type": "request", "id": id, "method": "approval.revoke",
        "params": { "store": "swarm", "key": SITE, "what": "grant" },
        "context": { "caller": "chrome" },
    }));
    let reply = main.core.response(id);
    assert_eq!(reply["error"]["code"], "storage", "{reply}");
    assert_eq!(
        reply["error"]["data"],
        json!({ "store": "swarm", "applied": true })
    );
    std::fs::write(&hook, "").unwrap();
    assert_eq!(record_of(&mut main, SITE), JsValue::Null);
    let file = std::fs::read_to_string(root.join("swarm-permissions.json")).unwrap();
    assert!(!file.contains(SITE), "the detach wrote the file: {file}");
    told_once(&mut main, SITE);
    main.settled();
    let mut main = main.restart(&env);
    assert!(!grants_read(&mut main).contains_key(SITE));
    assert_eq!(record_of(&mut main, SITE), JsValue::Null);
    assert!(!feeds_on_disk(&root).has_feed_grant(&JsString::from(SITE)));
    main.settled();
}

/// D17: a manifest's own projections detach nothing: a decision's
/// connection and rule, which the swarm thread writes, and main's own
/// grant writes (`shell`, a manifest's projection under the old path).
#[test]
fn a_manifest_s_own_projections_detach_nothing() {
    let mut main = swarm_world::main();
    main.world(json!({ "reset": true, "clock": T0 }));
    no_manifests(&mut main);
    let mut own = OwnMain::new(|call, _| panic!("{call:?}"));
    own.manifest = Box::new(|_| Some(fetched(200, MANIFEST.as_bytes())));
    let answer = value_of(got(&main.play_own(
        &mut own,
        "swarm.manifest",
        &check(),
        "shell",
    )));
    let decide = op_params(
        "decide",
        &[
            ("key", JsValue::string(SITE)),
            ("token", field(&answer, "token").clone()),
            ("outcome", JsValue::string("allow")),
            ("live", JsValue::Bool(true)),
        ],
    );
    let mut own = OwnMain::new(|call, _| panic!("{call:?}"));
    main.play_own(&mut own, "swarm.manifest", &decide, "shell");
    let decided = record_of(&mut main, SITE);
    assert_eq!(
        field(&decided, "managed").stringify(),
        r#"{"connection":["publish"],"autoApprove.publish":["publish"]}"#
    );
    assert!(decided.get("detached").is_none(), "{}", decided.stringify());
    let shell = json!({ "caller": "shell" });
    let grant =
        json!({ "store": "swarm", "change": { "op": "flag", "flag": "publish", "key": SITE } });
    approval(&mut main, "approval.grant", grant, shell.clone());
    let revoke = json!({ "store": "swarm", "key": SITE, "what": { "flag": "signing" } });
    approval(&mut main, "approval.revoke", revoke, shell);
    assert_eq!(record_of(&mut main, SITE).stringify(), decided.stringify());
    main.settled();
}

/// D17's order through the pipe: the chrome turns a rule off while main
/// holds a check's fetch; the detach waits for the check, which keeps the
/// record it read, and main's next op of the site waits for the detach.
#[test]
fn a_detach_waits_for_a_check_in_flight() {
    let mut main = swarm_world::main();
    let mut dir = Dir::new();
    dir.insert(
        manifests::FILE_NAME.to_owned(),
        format!(r#"{{"version":1,"records":{{"{SITE}":{MANAGED}}}}}"#),
    );
    set_up(&mut main, &dir, &connected(&[SITE]), T0);
    let check_id = main.own_request("swarm.manifest", &check(), "shell");
    let message = main.recv();
    assert_eq!(message["method"], "shell.swarm_manifest", "{message}");
    let fetch = message["id"].as_u64().unwrap();
    let revoke = json!({ "store": "swarm", "key": SITE, "what": { "flag": "publish" } });
    approval(&mut main, "approval.revoke", revoke, chrome());
    let get = main.own_request(
        "swarm.manifest",
        &op_params("get", &[("origin", JsValue::string(SITE))]),
        "shell",
    );
    // Neither answers while the fetch is out.
    let quiet = std::time::Instant::now() + std::time::Duration::from_millis(300);
    while let Some(wire) = main
        .core
        .recv_wire_within(quiet.saturating_duration_since(std::time::Instant::now()))
    {
        match wire {
            common::Wire::Message(message) if message["type"] == "event" => {
                main.core.events.push(message);
            }
            other => panic!("while the fetch is out: {other:?}"),
        }
    }
    main.answer(fetch, fetched(200, MANIFEST.as_bytes()));
    let first = main.recv();
    assert_eq!(first["id"], check_id, "{first}");
    assert_eq!(text_at(&value_of(got(&first)), "kind"), "ready");
    let second = main.recv();
    assert_eq!(second["id"], get, "{second}");
    let record = value_of(got(&second));
    assert!(record.get("observed").is_some(), "{}", record.stringify());
    assert_eq!(
        field(&record, "detached").stringify(),
        r#"{"autoApprove.publish":true}"#
    );
    assert_eq!(
        field(&record, "managed").stringify(),
        r#"{"connection":["publish"]}"#
    );
    assert_eq!(field(&record, "revision"), &JsValue::Number(2.0));
    told_once(&mut main, SITE);
    main.settled();
}

// --- D12's recorded cases: the `shell` section ---------------------------------------

fn shell_section() -> Vec<JsValue> {
    let text = std::fs::read_to_string(vectors_root().join("swarm.json")).unwrap();
    let index = Index::new(&text).unwrap();
    let shell = fc_json::parse(index.root().get("shell").unwrap().raw()).unwrap();
    shell.as_array().unwrap().to_vec()
}

fn num(value: &JsValue) -> f64 {
    match value {
        JsValue::Number(n) => *n,
        other => panic!("not a number: {}", short(other)),
    }
}

/// A typed answer as the core writes it, read back.
fn typed_answer(message: &Value) -> Result<Typed, Typed> {
    let read = |v: &Value| {
        Typed::from_typed(&fc_json::parse(&v.to_string()).unwrap())
            .unwrap_or_else(|e| panic!("{e}: {v}"))
    };
    let result = &message["result"];
    assert!(message.get("error").is_none(), "{message}");
    match (result.get("result_typed"), result.get("error_typed")) {
        (Some(v), None) => Ok(read(v)),
        (None, Some(e)) => Err(read(e)),
        _ => panic!("no typed answer: {message}"),
    }
}

/// A recorded answer: `{ result_typed }` or `{ error_typed }`.
fn recorded_answer(answer: &JsValue) -> Result<Typed, Typed> {
    match (answer.get("result_typed"), answer.get("error_typed")) {
        (Some(v), None) => Ok(Typed::from_typed(v).unwrap()),
        (None, Some(e)) => Err(Typed::from_typed(e).unwrap()),
        _ => panic!("no typed answer in {}", short(answer)),
    }
}

/// A recorded reply as main forwards it: the headers the core reads.
fn recorded_reply(reply: &JsValue, keep: &[&str]) -> Event {
    let headers = field(reply, "headers")
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let pair = pair.as_array().unwrap();
            (str_of(&pair[0]).to_owned(), str_of(&pair[1]).to_owned())
        })
        .filter(|(k, _)| keep.contains(&k.as_str()))
        .collect();
    Event::Reply(Reply {
        status: num(field(reply, "status")) as u16,
        status_text: str_of(field(reply, "status_text")).to_owned(),
        headers,
        body: logic::b64(str_of(field(field(reply, "body"), "base64"))),
    })
}

fn string_pairs(value: Option<&JsValue>) -> Vec<(String, String)> {
    value
        .map(|list| {
            list.as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    let pair = pair.as_array().unwrap();
                    (str_of(&pair[0]).to_owned(), str_of(&pair[1]).to_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A call the reference made, as the core makes it, and main's reply.
struct WantCall {
    form: String,
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    /// The body's bytes, or its length and SHA-256.
    body: Option<(usize, Result<Vec<u8>, String>)>,
    feed: Option<(String, u64)>,
    reply: Event,
}

/// The calls the core makes for a step's recorded requests: the
/// reference's own, its second `/stamps` dropped (`stamps-one-read`) and
/// its whole `GET /feeds` index lookup (an update's and a read's) asked as
/// `feed_head` (`index-probe`).
fn want_calls(step: &JsValue) -> Vec<WantCall> {
    let mut out = Vec::new();
    for r in field(step, "requests").as_array().unwrap() {
        let reply = field(r, "reply");
        match r.get("deviation").map(str_of) {
            Some("stamps-one-read") => continue,
            Some("index-probe") => out.push(WantCall {
                form: "feed_head".to_owned(),
                method: "GET".to_owned(),
                path: str_of(field(r, "path")).to_owned(),
                query: Vec::new(),
                headers: vec![("swarm-only-root-chunk".to_owned(), "true".to_owned())],
                body: None,
                feed: None,
                reply: recorded_reply(reply, &["swarm-feed-index", "swarm-feed-index-next"]),
            }),
            Some(other) => panic!("a shell request of deviation {other}"),
            None => out.push(WantCall {
                form: str_of(field(r, "form")).to_owned(),
                method: str_of(field(r, "method")).to_owned(),
                path: str_of(field(r, "path")).to_owned(),
                query: string_pairs(r.get("query")),
                headers: string_pairs(r.get("headers"))
                    .into_iter()
                    .filter(|(k, _)| k != "accept" && k != "accept-encoding")
                    .collect(),
                body: r.get("body").map(|b| {
                    let n = num(field(b, "bytes")) as usize;
                    match b.get("base64") {
                        Some(t) => (n, Ok(logic::b64(str_of(t)))),
                        None => (n, Err(str_of(field(b, "sha256")).to_owned())),
                    }
                }),
                feed: r.get("feed").map(|f| {
                    (
                        str_of(field(f, "owner")).to_owned(),
                        num(field(f, "index")) as u64,
                    )
                }),
                reply: recorded_reply(reply, &logic::READ_HEADERS),
            }),
        }
    }
    out
}

fn check_call(id: &str, k: usize, (call, body): &(NodeCall, Vec<u8>), want: &WantCall) {
    let at = format!("{id}: call {k}");
    assert_eq!(call.form.as_str(), want.form, "{at}");
    assert_eq!(call.method(), want.method, "{at}");
    assert_eq!(call.path, want.path, "{at}");
    assert_eq!(call.query, want.query, "{at}");
    assert_eq!(call.headers, want.headers, "{at}");
    match &want.body {
        None => assert!(body.is_empty(), "{at}: a body where none"),
        Some((n, Ok(bytes))) => {
            assert_eq!(body.len(), *n, "{at}");
            assert!(body == bytes, "{at}: the body's bytes");
        }
        Some((n, Err(digest))) => {
            assert_eq!(body.len(), *n, "{at}");
            assert_eq!(logic::sha(body), *digest, "{at}");
        }
    }
    if let Some((owner, index)) = &want.feed {
        let feed = call
            .feed
            .as_ref()
            .unwrap_or_else(|| panic!("{at}: no feed"));
        assert_eq!(
            (logic::hex(&feed.owner), feed.index),
            (owner.clone(), *index),
            "{at}"
        );
    }
}

/// Every `shell` case of `vectors/swarm.json` (D12's, recorded from the
/// reference's services, IPC handlers and functions) through the core, one
/// core playing each group (D11):
///
/// - **main's node methods** (`swarm.publish`, `swarm.feed`, `swarm.stamps`,
///   `swarm.upload_status`): main's params as the case gives them; each of
///   the core's node calls against the reference's (form, method, path,
///   query, headers, body, a probe's feed update), answered with the
///   node's recorded reply, and within the case's row in
///   `swarm-grammar.json`; parts streamed through `shell.swarm_part`, and
///   a picked file's read failing with its errno's name; the answer
///   (typed), and the history `swarm.history` reads after;
/// - **the store ops** (`swarm.identities`, `swarm.history`,
///   `swarm.manifest`): each step's params and caller, the vault's owners
///   from the core's own vault and the user's accounts from the core's
///   `vault-meta.json`, a check's fetch answered as main answered it (D6);
///   each answer (typed; a consent's token, the core's own randomness, read
///   as the recorded one, and handed back in its place), the files as each
///   step answered, and the files, grants and history rows after.
///
/// Deviation cases are held to their `core` answers. The case whose steps
/// run at once (`owner-read-order`) runs on a core that holds the vault's
/// owners until its second step has answered.
#[test]
fn every_shell_case_through_the_pipe() {
    let cases = shell_section();
    let grammar_text = logic::text_of("swarm-grammar.json");
    let grammar_index = Index::new(&grammar_text).unwrap();
    let grammar = grammar_index.root();
    let mut main = store_main();
    let mut played: BTreeMap<String, usize> = BTreeMap::new();
    for case in &cases {
        let method = str_of(field(case, "method"));
        if case.get("concurrent").is_some() {
            play_concurrent(case);
        } else if ["swarm.identities", "swarm.history", "swarm.manifest"].contains(&method) {
            play_shell_op(&mut main, case);
        } else {
            play_shell_node(&mut main, case, grammar);
        }
        *played.entry(method.to_owned()).or_default() += 1;
    }
    let counts: Vec<(&str, usize)> = played.iter().map(|(k, n)| (k.as_str(), *n)).collect();
    assert_eq!(
        counts,
        [
            ("swarm.feed", 19),
            ("swarm.history", 4),
            ("swarm.identities", 21),
            ("swarm.manifest", 15),
            ("swarm.publish", 20),
            ("swarm.stamps", 5),
            ("swarm.upload_status", 4),
        ]
    );
}

/// The calls' forms within `row`'s in the grammar file, in order and
/// within their counts (common's `check_row_shape`).
fn within_row(id: &str, grammar: V<'_, '_>, row: &str, calls: &[(NodeCall, Vec<u8>)]) {
    let ran = logic::Ran {
        outcome: fc_swarm_provider::machine::Outcome::Cancelled,
        ready: Vec::new(),
        calls: calls
            .iter()
            .map(|(call, _)| logic::Logged {
                call: call.clone(),
                charge: 0,
                body: None,
            })
            .collect(),
        cancels_after_outcome: 0,
        most_open: 0,
    };
    logic::check_row_shape(id, grammar, row, &ran);
}

fn play_shell_node(main: &mut Main, case: &JsValue, grammar: V<'_, '_>) {
    let id = str_of(field(case, "id"));
    let world = field(case, "world");
    let clock = num(field(world, "clock")) as u64;
    let deviation = case.get("deviation").map(str_of);
    let picked_read = deviation == Some("picked-read-text");
    // The owner main names isn't the vault's Bee wallet (K2): the core
    // refuses before any node call.
    let feed_owner = deviation == Some("feed-owner");
    match deviation {
        None => assert!(case.get("core").is_none(), "{id}"),
        Some("picked-read-text" | "index-probe" | "feed-owner") => {}
        Some(other) => panic!("{id}: deviation {other}"),
    }
    main.world(json!({ "reset": true, "clock": clock }));
    let locked = str_of(field(world, "vault")) == "locked";
    if locked {
        main.set_vault(false);
    }
    let steps = field(case, "steps").as_array().unwrap();
    assert_eq!(steps.len(), 1, "{id}");
    let step = &steps[0];
    let wants = if feed_owner {
        Vec::new()
    } else {
        want_calls(step)
    };
    let replies: Vec<Event> = wants.iter().map(|w| w.reply.clone()).collect();
    let mut n = 0usize;
    let mut own = OwnMain::new(move |call: &NodeCall, _: &[u8]| {
        let reply = replies
            .get(n)
            .unwrap_or_else(|| panic!("an unrecorded call {} {}", call.method(), call.path))
            .clone();
        n += 1;
        reply
    });
    if let Some(parts) = step.get("parts") {
        for (k, part) in parts.as_array().unwrap().iter().enumerate() {
            own.parts
                .insert(k as u32, logic::b64(str_of(field(part, "base64"))));
        }
    }
    if let Some(abort) = step.get("part_abort") {
        let part = num(field(abort, "part")) as u32;
        let code: &'static str = Box::leak(str_of(field(abort, "error_code")).into());
        own.parts.entry(part).or_default();
        own.abort_part = Some((part, code));
    }
    let params = json_of(field(step, "params"));
    let answer = main.play_own(&mut own, str_of(field(case, "method")), &params, "shell");
    within_row(id, grammar, str_of(field(case, "row")), &own.calls);
    let extra = usize::from(picked_read);
    assert_eq!(own.calls.len(), wants.len() + extra, "{id}");
    for (k, (got, want)) in own.calls.iter().zip(&wants).enumerate() {
        check_call(id, k, got, want);
    }
    let core = case.get("core").filter(|_| picked_read || feed_owner);
    let want = match core {
        Some(core) => &field(core, "answers").as_array().unwrap()[0],
        None => field(step, "answer"),
    };
    assert_eq!(typed_answer(&answer), recorded_answer(want), "{id}");
    let rows = match core.filter(|_| picked_read) {
        Some(core) => field(core, "history"),
        None => field(field(case, "after"), "history"),
    };
    assert_eq!(
        JsValue::Array(history_rows(main)).stringify(),
        rows.stringify(),
        "{id}: the history"
    );
    if locked {
        main.set_vault(true);
    }
}

/// A consent's token in an answer: the core's own, read as the recorded
/// one (`tokens` maps the recorded to the core's, for the steps after).
fn with_tokens(
    value: &mut Typed,
    want: &Result<Typed, Typed>,
    tokens: &mut BTreeMap<String, String>,
) {
    let (Typed::Object(members), Ok(Typed::Object(wanted))) = (value, want) else {
        return;
    };
    let recorded = wanted.iter().find_map(|(k, v)| match v {
        Typed::String(s) if k == "token" => Some(s.as_str().to_owned()),
        _ => None,
    });
    for (k, v) in members.iter_mut() {
        if k == "token"
            && let (Typed::String(core), Some(recorded)) = (&*v, &recorded)
        {
            tokens.insert(recorded.clone(), core.as_str().to_owned());
            *v = Typed::str(recorded);
        }
    }
}

/// The recorded tokens in a step's params replaced by the core's.
fn tokens_in(params: Value, tokens: &BTreeMap<String, String>) -> Value {
    let mut text = params.to_string();
    for (recorded, core) in tokens {
        text = text.replace(recorded, core);
    }
    serde_json::from_str(&text).unwrap()
}

/// The world a store-op case starts from: the files, the grants, the
/// accounts, the history's rows, the clock and the vault.
fn set_up_shell_op(main: &mut Main, id: &str, case: &JsValue) -> bool {
    let world = field(case, "world");
    let clock = num(field(world, "clock")) as u64;
    let mut files = Dir::new();
    if let Some(text) = field(world, "feeds").as_str() {
        files.insert(feeds::FILE_NAME.to_owned(), text.to_owned());
    }
    if let Some(text) = field(world, "manifests").as_str() {
        files.insert(manifests::FILE_NAME.to_owned(), text.to_owned());
    }
    // accounts.list's wallets, as the core reads them from main's
    // vault-meta.json: kept as recorded (not derived from the vault's
    // mnemonic), so each is stored as a device's.
    let meta = main.data_dir().join(fc_wallet_state::vault_meta::FILE_NAME);
    let _ = std::fs::remove_file(&meta);
    if let Some(accounts) = world.get("accounts") {
        let wallets: Vec<Value> = accounts
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let mut w = json_of(a);
                w["type"] = json!("ledger");
                w
            })
            .collect();
        std::fs::write(&meta, json!({ "derivedWallets": wallets }).to_string()).unwrap();
    }
    set_up(main, &files, field(world, "grants"), clock);
    if let Some(rows) = world.get("history") {
        let conn = history_db(&main.core.grant_root);
        for row in rows.as_array().unwrap() {
            let JsValue::Object(cells) = row else {
                panic!("{id}: a row")
            };
            let names: Vec<&str> = cells.iter().map(|(k, _)| k.as_str()).collect();
            let values: Vec<rusqlite::types::Value> = cells
                .iter()
                .map(|(_, v)| match v {
                    JsValue::Null => rusqlite::types::Value::Null,
                    JsValue::Number(n) if n.fract() == 0.0 => {
                        rusqlite::types::Value::Integer(*n as i64)
                    }
                    JsValue::Number(n) => rusqlite::types::Value::Real(*n),
                    JsValue::String(t) => rusqlite::types::Value::Text(t.as_str().to_owned()),
                    blob => rusqlite::types::Value::Blob(hex_bytes(str_of(field(blob, "blob")))),
                })
                .collect();
            let sql = format!(
                "INSERT INTO publishes ({}) VALUES ({})",
                names.join(", "),
                vec!["?"; names.len()].join(", ")
            );
            conn.execute(&sql, rusqlite::params_from_iter(values))
                .unwrap();
        }
    }
    let locked = str_of(field(world, "vault")) == "locked";
    if locked {
        main.set_vault(false);
    }
    locked
}

/// The files as a step answered, or as the case leaves them.
fn check_shell_files(main: &Main, at: &str, want: &JsValue) {
    let root = &main.core.grant_root;
    for (name, file) in [
        ("feeds", feeds::FILE_NAME),
        ("manifests", manifests::FILE_NAME),
    ] {
        assert_eq!(
            std::fs::read_to_string(root.join(file)).ok().as_deref(),
            field(want, name).as_str(),
            "{at}: {name}"
        );
    }
}

/// The history's rows, each cell as stored.
fn stored_rows(root: &Path) -> JsValue {
    let conn = history_db(root);
    JsValue::Array(
        query(
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
        .collect(),
    )
}

/// One store-op step through the pipe: its fetch answered as main answered
/// it.
fn shell_op_step(main: &mut Main, method: &str, step: &JsValue, params: &Value) -> Value {
    let fetch = step
        .get("fetch")
        .filter(|f| !matches!(f, JsValue::Null))
        .cloned();
    let mut own = OwnMain::new(|call, _| panic!("a store op called the node: {call:?}"));
    own.manifest = Box::new(move |url: &str| {
        let fetch = fetch
            .clone()
            .unwrap_or_else(|| panic!("an unrecorded fetch of {url}"));
        assert_eq!(url, str_of(field(&fetch, "url")));
        Some(json_of(field(&fetch, "answer")))
    });
    main.play_own(&mut own, method, params, str_of(field(step, "caller")))
}

fn play_shell_op(main: &mut Main, case: &JsValue) {
    let id = str_of(field(case, "id"));
    let method = str_of(field(case, "method"));
    let deviation = case.get("deviation").map(str_of);
    let core = case.get("core");
    let mut locked = set_up_shell_op(main, id, case);
    let mut tokens = BTreeMap::new();
    let steps = field(case, "steps").as_array().unwrap();
    for (k, step) in steps.iter().enumerate() {
        if let Some(clock) = step.get("clock") {
            main.world(json!({ "clock": num(clock) as u64 }));
        }
        if let Some(vault) = step.get("vault") {
            let unlocked = str_of(vault) == "unlocked";
            if unlocked == locked {
                main.set_vault(unlocked);
                locked = !unlocked;
            }
        }
        let want = match deviation {
            Some("collation" | "history-blobs") => {
                recorded_answer(&field(core.unwrap(), "answers").as_array().unwrap()[k])
            }
            _ => recorded_answer(field(step, "answer")),
        };
        let params = tokens_in(json_of(field(step, "params")), &tokens);
        let message = shell_op_step(main, method, step, &params);
        let mut got = typed_answer(&message);
        if let Ok(value) = &mut got {
            with_tokens(value, &want, &mut tokens);
        }
        assert_eq!(got, want, "{id} step {k}");
        if let Some(files) = step.get("files") {
            let want = match deviation {
                Some("detach-timing") => &field(core.unwrap(), "files").as_array().unwrap()[k],
                _ => files,
            };
            check_shell_files(main, &format!("{id} step {k}"), want);
        }
    }
    if locked {
        main.set_vault(true);
    }
    let after = field(case, "after");
    check_shell_files(main, &format!("{id}: after"), after);
    let want_grants: BTreeMap<String, Value> = match json_of(field(after, "grants")) {
        Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), reads(v))).collect(),
        other => panic!("{id}: grants {other}"),
    };
    assert_eq!(grants_read(main), want_grants, "{id}: grants");
    if let Some(rows) = after.get("history") {
        assert_eq!(
            stored_rows(&main.core.grant_root).stringify(),
            rows.stringify(),
            "{id}: the rows"
        );
    }
    let _ = std::fs::remove_file(main.data_dir().join(fc_wallet_state::vault_meta::FILE_NAME));
}

/// `owner-read-order`: step 1 runs while step 0's owners are read, on a
/// core that holds the vault's owners (`FREEDOM_CORED_TEST_SWARM_HOLD`)
/// until step 1 has answered; step 0's answer is read when its last owner
/// arrives, step 1's change in it.
fn play_concurrent(case: &JsValue) {
    let id = str_of(field(case, "id"));
    assert_eq!(
        case.get("deviation").map(str_of),
        Some("owner-read-order"),
        "{id}"
    );
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("parked");
    let release = dir.path().join("release");
    let hold = format!("owner={}={}", marker.display(), release.display());
    let mut main = swarm_world::main_with(
        &["swarm"],
        &[("FREEDOM_CORED_TEST_SWARM_HOLD", hold.as_str())],
    );
    main.import_vault();
    set_up_shell_op(&mut main, id, case);
    let method = str_of(field(case, "method"));
    let steps = field(case, "steps").as_array().unwrap();
    let answers = field(field(case, "core"), "answers").as_array().unwrap();
    let first = main.own_request(
        method,
        &json_of(field(&steps[0], "params")),
        str_of(field(&steps[0], "caller")),
    );
    while std::fs::read_to_string(&marker)
        .unwrap_or_default()
        .is_empty()
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let second = main.own_request(
        method,
        &json_of(field(&steps[1], "params")),
        str_of(field(&steps[1], "caller")),
    );
    let message = main.core.response(second);
    assert_eq!(
        typed_answer(&message),
        recorded_answer(&answers[1]),
        "{id} step 1"
    );
    std::fs::write(&release, "").unwrap();
    let message = main.core.response(first);
    assert_eq!(
        typed_answer(&message),
        recorded_answer(&answers[0]),
        "{id} step 0"
    );
    main.settled();
    let after = field(case, "after");
    check_shell_files(&main, &format!("{id}: after"), after);
}

/// Answers waiting for the writer hold new requests (design 0001's
/// backpressure, as the vault loop's): main pipelines `get-all-origins` (no
/// place in the gate) over a feed store of a few MiB while it doesn't
/// read; the thread answers until the writer's allowances are full, then
/// takes no new request while an answer waits, each keeping its frame's
/// credit, so the answers that wait for the writer at once stay one
/// answer's bytes, not every pipelined call's.
#[test]
fn answers_waiting_for_the_writer_hold_new_requests() {
    let mut main = swarm_world::main();
    a_large_feed_store(&mut main);
    let calls = 24;
    main.core.pause_reading();
    let ids = pipelined_origins(&mut main, calls);
    // Time for an unbounded thread to answer every one.
    std::thread::sleep(std::time::Duration::from_secs(6));
    main.core.resume_reading();
    let mut largest = 0;
    for id in &ids {
        let message = main.recv();
        assert_eq!(message["id"], *id, "in order");
        let size = message.to_string().len();
        largest = largest.max(size);
        let Got::Value(JsValue::Array(ref sites)) = got(&message) else {
            panic!("an answer")
        };
        assert_eq!(sites.len(), SITES);
    }
    let held = main.world(json!({ "answers": true }));
    let most = held["answers_waiting_most"].as_u64().unwrap() as usize;
    // The answers are over twice the writer's 32 MiB allowance: unbounded,
    // over 32 MiB of them would wait at once.
    assert!(
        largest * calls > 2 * (32 << 20),
        "{largest} bytes an answer"
    );
    assert!(
        most <= largest + (64 << 10),
        "{most} bytes waited at once, an answer is {largest}"
    );
    main.settled();
}

/// A main that stops reading for good ends the core (design 0001's stall
/// bound, 30 s, 3 s here), as the vault loop's replies do: the Swarm
/// answers wait past the writer's allowances, new requests are held, and
/// nothing else bounds the wait (`get-all-origins` has no deadline); once
/// the writer has written nothing for the bound, the core exits 76.
#[test]
fn a_main_that_never_reads_again_ends_the_core() {
    let mut main = swarm_world::main_with(&["swarm"], &[("FREEDOM_CORED_TEST_STALL_MS", "3000")]);
    a_large_feed_store(&mut main);
    main.core.pause_reading();
    let started = std::time::Instant::now();
    pipelined_origins(&mut main, 24);
    // Within the bound: alive.
    std::thread::sleep(std::time::Duration::from_millis(1000));
    assert!(
        main.core.child.try_wait().unwrap().is_none(),
        "exited early"
    );
    assert_eq!(main.core.exit_code(std::time::Duration::from_secs(20)), 76);
    // With slack, as for the thread's other bounds.
    assert!(
        started.elapsed() + std::time::Duration::from_millis(2)
            >= std::time::Duration::from_secs(3)
    );
    let stderr = main.core.stderr();
    let line = stderr
        .lines()
        .find(|line| line.contains("main is not reading replies"))
        .unwrap_or_else(|| panic!("no stall line: {stderr}"));
    assert!(line.contains(r#""frames":"swarm""#), "{line}");
}

/// The sites in [`a_large_feed_store`].
const SITES: usize = 9000;

/// A feed store of a few MiB, loaded: each `get-all-origins` answer is
/// that large.
fn a_large_feed_store(main: &mut Main) {
    main.world(json!({ "reset": true, "clock": T0 }));
    let mut origins = serde_json::Map::new();
    for i in 0..SITES {
        origins.insert(
            format!("https://site-{i}.example"),
            json!({
                "activeIdentityId": "bee-wallet",
                "identities": { "bee-wallet": {
                    "id": "bee-wallet", "mode": "bee-wallet", "publisherKeyIndex": null,
                    "walletIndex": null, "label": "Bee wallet identity", "createdAt": 1, "lastUsedAt": null,
                } },
                "feedGranted": true, "grantedAt": 1, "feeds": {},
            }),
        );
    }
    let text = json!({ "version": 2, "nextPublisherKeyIndex": 0, "origins": origins }).to_string();
    assert!(text.len() > 1 << 20, "{} bytes", text.len());
    std::fs::write(main.core.grant_root.join(feeds::FILE_NAME), &text).unwrap();
    main.world(json!({ "reload": true }));
}

/// Main's `calls` pipelined `get-all-origins` calls, not read: their IDs.
fn pipelined_origins(main: &mut Main, calls: usize) -> Vec<u64> {
    (0..calls)
        .map(|_| {
            main.own_request(
                "swarm.identities",
                &op_params("get-all-origins", &[]),
                "chrome",
            )
        })
        .collect()
}

/// Nothing is signed after main's cancel (design 0015, "Deadlines and
/// cancel"): `swarm.feed`'s update reaches its signature, whose ask waits
/// on the event loop (the test hooks' `ask` hold) as one queued behind a
/// cancel does; main cancels; the ask then reaches the vault, which signs
/// nothing for a cancelled request.
#[test]
fn a_cancel_before_a_queued_signature_signs_nothing() {
    let mut signing = Signing::new("ask", &[]);
    let request = own_update_to_its_signature(&mut signing.main);
    // The signature's ask waits on the loop; then main's cancel.
    wait_for(&signing.marker);
    signing
        .main
        .core
        .send(&json!({ "type": "cancel", "id": request }));
    let reply = signing.main.core.response(request);
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    std::fs::write(&signing.release, "").unwrap();
    // The ask reaches the vault, which refuses it; the thread drops the
    // refusal; nothing was signed.
    std::thread::sleep(std::time::Duration::from_millis(200));
    signing.main.settled();
    assert_eq!(signing.signed(), "");
    // Without a cancel, the same update signs once.
    let request = own_update_to_its_signature(&mut signing.main);
    let soc = signing.main.recv();
    assert_eq!(soc["params"]["form"], "soc_up", "{soc}");
    answer_the_soc(&mut signing.main, &soc);
    let answer = signing.main.core.response(request);
    assert!(answer["result"]["result_typed"].is_object(), "{answer}");
    assert_eq!(signing.signed(), "sign\n");
}

/// A request's end and the vault's signature don't interleave (design
/// 0015, "Deadlines and cancel"): the vault checks the request and signs
/// holding its state, which its end takes too. Ended while the vault
/// stops just before that check (`presign`; the request's deadline, on
/// the swarm thread, as the loop is the vault's), main's own SOC is never
/// signed. Ended while it signs (`signing`), the end waits for the
/// signature, which is made once: the deadline's answer comes only after,
/// and main's cancel is read only after.
#[test]
fn an_end_and_main_s_own_signature_are_one_before_the_other() {
    const DEADLINE: (&str, &str) = ("FREEDOM_CORED_TEST_SWARM_DEADLINE_MS", "1000");
    // The deadline before the check: nothing signed.
    let mut signing = Signing::new("presign", &[DEADLINE]);
    let request = own_update_to_its_signature(&mut signing.main);
    wait_for(&signing.marker);
    let reply = signing.main.core.response(request);
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    std::fs::write(&signing.release, "").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    signing.main.settled();
    assert_eq!(signing.signed(), "");

    // The deadline while it signs: the end waits, signed once.
    let mut signing = Signing::new("signing", &[DEADLINE]);
    let request = own_update_to_its_signature(&mut signing.main);
    wait_for(&signing.marker);
    assert_eq!(
        signing
            .main
            .core
            .recv_or_closed(std::time::Duration::from_millis(2000)),
        Ok(None),
        "the deadline's end waits for the signature"
    );
    std::fs::write(&signing.release, "").unwrap();
    let reply = signing.main.core.response(request);
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    signing.main.settled();
    assert_eq!(signing.signed(), "sign\n");

    // Main's cancel while it signs: signed once, then cancelled.
    let mut signing = Signing::new("signing", &[]);
    let request = own_update_to_its_signature(&mut signing.main);
    wait_for(&signing.marker);
    signing
        .main
        .core
        .send(&json!({ "type": "cancel", "id": request }));
    std::thread::sleep(std::time::Duration::from_millis(200));
    std::fs::write(&signing.release, "").unwrap();
    assert_eq!(
        until_cancelled(&mut signing.main, request),
        1,
        "the signed SOC's upload went"
    );
    signing.main.settled();
    assert_eq!(signing.signed(), "sign\n");
}

/// A core whose vault signs for main's own `swarm.feed` with the test
/// hooks' hold of `kind` (`ask`, `presign` or `signing`) and `env`: the
/// hold's marker and release, and the signatures' marker.
struct Signing {
    main: Main,
    marker: PathBuf,
    release: PathBuf,
    signs: PathBuf,
    _dir: tempfile::TempDir,
}

impl Signing {
    fn new(kind: &str, env: &[(&str, &str)]) -> Signing {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("parked");
        let release = dir.path().join("release");
        let signs = dir.path().join("signs");
        let hold = format!("{kind}={}={}", marker.display(), release.display());
        let mut envs = vec![
            ("FREEDOM_CORED_TEST_SWARM_HOLD", hold.as_str()),
            (
                "FREEDOM_CORED_TEST_SWARM_SIGN_MARKER",
                signs.to_str().unwrap(),
            ),
        ];
        envs.extend_from_slice(env);
        let mut main = swarm_world::main_with(&["swarm"], &envs);
        main.import_vault();
        main.world(json!({ "reset": true, "clock": T0 }));
        Signing {
            main,
            marker,
            release,
            signs,
            _dir: dir,
        }
    }

    /// The signatures made, a line each.
    fn signed(&self) -> String {
        std::fs::read_to_string(&self.signs).unwrap_or_default()
    }
}

/// Waits for the hold's first line on `marker`.
fn wait_for(marker: &Path) {
    while std::fs::read_to_string(marker)
        .unwrap_or_default()
        .is_empty()
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Main's own update, its feed's head answered: it goes on to its
/// signature. The request's ID.
fn own_update_to_its_signature(main: &mut Main) -> u64 {
    let update = json!({
        "op": "update", "key": { "kind": "bee_wallet" }, "owner": bee_owner(),
        "topic": "77".repeat(32), "reference": "ef".repeat(32), "batch": "a1".repeat(32),
    });
    let request = main.own_request("swarm.feed", &update, "shell");
    let call = main.recv();
    assert_eq!(call["method"], "shell.swarm_api", "{call}");
    assert_eq!(call["params"]["form"], "feed_head");
    main.answer(
        call["id"].as_u64().unwrap(),
        json!({
            "status": 200, "status_text": "OK",
            "headers": [["swarm-feed-index", "0000000000000002"], ["swarm-feed-index-next", "0000000000000003"]],
            "body_base64": "",
        }),
    );
    request
}

/// The node takes the signed SOC `soc` (its call): its reference.
fn answer_the_soc(main: &mut Main, soc: &Value) {
    let address = soc["params"]["path"].as_str().unwrap().to_owned();
    let segments: Vec<&str> = address.split('/').collect();
    let owner: [u8; 20] = logic::unhex(segments[2]).try_into().unwrap();
    let id: [u8; 32] = logic::unhex(segments[3]).try_into().unwrap();
    let reference = logic::hex(&fc_swarm::verify::soc_address(&id, &owner));
    main.answer(
        soc["id"].as_u64().unwrap(),
        json!({
            "status": 201, "status_text": "Created",
            "headers": [["content-type", "application/json"]],
            "body_base64": fc_swarm_provider::value::encode_base64(format!(r#"{{"reference":"{reference}"}}"#).as_bytes()),
        }),
    );
}

/// Reads until main's `request` is answered `cancelled`, the core's calls
/// meanwhile left unanswered and refused once the core cancels them: how
/// many calls it made.
fn until_cancelled(main: &mut Main, request: u64) -> usize {
    let mut calls = 0;
    loop {
        let message = main.recv();
        match message["type"].as_str() {
            Some("request") => calls += 1,
            Some("cancel") => main.refuse(
                message["id"].as_u64().unwrap(),
                json!({ "code": "cancelled", "message": "Cancelled" }),
            ),
            Some("response") if message["id"] == request => {
                assert_eq!(message["error"]["code"], "cancelled", "{message}");
                return calls;
            }
            _ => panic!("{message}"),
        }
    }
}
