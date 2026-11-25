//! fc-swarm-provider's stores against vectors/swarm.json's `stores`
//! (design 0015, SWM-3's done-when: "`stores` pass"): every case of the
//! closed set of kinds, `feeds` (23), `manifests` (15) and `history` (6),
//! replayed through the codecs over a directory the test keeps, with the
//! reference's clock and the world the generator scripted
//! (vectors/generator/swarm-sections.js, `buildStores`).
//!
//! - **feeds:** the file and its backups from `before`, `FeedStore::load`,
//!   each operation's result or error, and every `swarm-feeds*` file after.
//! - **manifests:** the grants (the generator's grant mirror,
//!   swarm-world.js's `grantStore`), the feed store and the files; each
//!   step through `ManifestStore`, its effects applied as the world applies
//!   them; the results, the grants after and the files after.
//! - **history:** the statements run through SQLite (rusqlite, bundled, as
//!   freedom-cored links it): the open's import, sweep and bound, each
//!   operation's answer, and the schema, pragmas, rows and legacy files
//!   after.
//!
//! The deviation cases are asserted on the core's side (`core`):
//! `index-allocation` (the counter behind a held index) and `history-bound`
//! (10,001 rows).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fc_json::index::Index;
use fc_json::{JsString, JsValue};
use fc_swarm_provider::stores::feeds::{self, FeedStore, LoadWrite, Owners, Source};
use fc_swarm_provider::stores::history::{self, Bind, Cell, Legacy, LegacyFile, Statement};
use fc_swarm_provider::stores::manifests::{
    self, Capability, CheckStep, Effect, Fetched, ManifestError, ManifestStore, Owner, Reads, Save,
    World,
};
use fc_swarm_provider::stores::{StoreError, Thrown};

/// The cases' clock (`swarm-cases.js`'s `T0`); the history runs' is a
/// second later.
const T0: u64 = 1_767_225_600_123;

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

/// `swarm.json`'s `stores` and `deviations`, as JavaScript values.
fn sections() -> (Vec<JsValue>, JsValue) {
    let text = std::fs::read_to_string(vectors_root().join("swarm.json")).unwrap();
    let index = Index::new(&text).unwrap();
    let root = index.root();
    let stores = fc_json::parse(root.get("stores").unwrap().raw()).unwrap();
    let deviations = fc_json::parse(root.get("deviations").unwrap().raw()).unwrap();
    (stores.as_array().unwrap().to_vec(), deviations)
}

fn field<'v>(value: &'v JsValue, key: &str) -> &'v JsValue {
    value
        .get(key)
        .unwrap_or_else(|| panic!("no {key:?} in {}", short(value)))
}

fn short(value: &JsValue) -> String {
    let text = value.stringify();
    text.chars().take(300).collect()
}

fn str_of(value: &JsValue) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {}", short(value)))
}

/// `formats.typed`'s values the stores' arguments use.
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
        "number" => JsValue::Number(match str_of(inner) {
            "NaN" => f64::NAN,
            "Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            "-0" => -0.0,
            n => n.parse().unwrap(),
        }),
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

/// The answer a step expects: `result`, `result_typed`, or `error`.
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

/// An answer, compared as `JSON.stringify` writes both (key order
/// included; `undefined` as itself).
fn assert_answer(case: &str, step: usize, got: Result<JsValue, Thrown>, want: &Expected) {
    match (got, want) {
        (Ok(got), Expected::Value(want)) => {
            if matches!(want, JsValue::Undefined) {
                assert_eq!(got, JsValue::Undefined, "{case} step {step}");
            } else {
                assert_eq!(got.stringify(), want.stringify(), "{case} step {step}");
            }
        }
        (Err(got), Expected::Error(want)) => {
            assert_eq!(
                got.name.as_str(),
                str_of(field(want, "name")),
                "{case} step {step}"
            );
            assert_eq!(
                got.message,
                str_of(field(want, "message")),
                "{case} step {step}"
            );
            let code = want.get("code").map(str_of);
            assert_eq!(got.code, code, "{case} step {step}");
            for key in ["status", "statusText", "reason", "limit", "actual"] {
                assert!(want.get(key).is_none(), "{case} step {step}: {key}");
            }
        }
        (got, want) => panic!("{case} step {step}: got {got:?}, want {want:?}"),
    }
}

fn thrown(error: StoreError) -> Thrown {
    match error {
        StoreError::Thrown(thrown) => thrown,
        StoreError::Full => panic!("store_full in a vector case"),
    }
}

/// A directory: each file's text.
type Dir = BTreeMap<String, String>;

fn text_map(value: &JsValue) -> Dir {
    fc_swarm_provider_props(value)
        .iter()
        .map(|(name, text)| (name.as_str().to_owned(), str_of(text).to_owned()))
        .collect()
}

fn fc_swarm_provider_props(value: &JsValue) -> &[(JsString, JsValue)] {
    match value {
        JsValue::Object(props) => props,
        JsValue::Null => &[],
        other => panic!("not an object: {}", short(other)),
    }
}

fn files_with(dir: &Dir, keep: impl Fn(&str) -> bool) -> Dir {
    dir.iter()
        .filter(|(name, _)| keep(name))
        .map(|(name, text)| (name.clone(), text.clone()))
        .collect()
}

#[test]
fn every_stores_case() {
    let (cases, deviations) = sections();
    let mut kinds: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for case in &cases {
        kinds
            .entry(str_of(field(case, "kind")).to_owned())
            .or_default()
            .push(str_of(field(case, "id")).to_owned());
    }
    // The closed set: a new or misspelled kind fails here.
    let counts: Vec<(&str, usize)> = kinds
        .iter()
        .map(|(k, ids)| (k.as_str(), ids.len()))
        .collect();
    assert_eq!(counts, [("feeds", 23), ("history", 6), ("manifests", 15)]);
    let keys = feeds_keys();
    let mut played = 0;
    for case in &cases {
        let id = str_of(field(case, "id"));
        match str_of(field(case, "kind")) {
            "feeds" => play_feeds(case, &keys),
            "manifests" => play_manifests(case),
            "history" => play_history(case),
            other => panic!("{id}: kind {other}"),
        }
        played += 1;
    }
    assert_eq!(played, 44);
    // The deviations the stores mark, and only those.
    let marked: Vec<(String, String)> = cases
        .iter()
        .filter_map(|case| {
            case.get("deviation")
                .map(|d| (str_of(d).to_owned(), str_of(field(case, "id")).to_owned()))
        })
        .collect();
    assert_eq!(
        marked,
        [
            (
                "index-allocation".to_owned(),
                "feeds-create-app-scoped-counter-behind".to_owned()
            ),
            ("history-bound".to_owned(), "history-10001-rows".to_owned()),
        ]
    );
    for (deviation, id) in &marked {
        let listed = field(field(&deviations, deviation), "cases");
        assert_eq!(listed.stringify(), format!("[\"stores/{id}\"]"));
    }
    assert!(field(&deviations, "store-writes").get("note").is_some());
}

// --- feeds ---------------------------------------------------------------------

/// keys.json's `abandon-12`: the Bee wallet's address and the publisher
/// keys', which the world's vault answers while unlocked.
struct VaultKeys {
    bee: String,
    publishers: BTreeMap<u64, String>,
}

fn feeds_keys() -> VaultKeys {
    let text = std::fs::read_to_string(vectors_root().join("keys.json")).unwrap();
    let keys = fc_json::parse(&text).unwrap();
    let vector = field(&keys, "vectors")
        .as_array()
        .unwrap()
        .iter()
        .find(|v| field(v, "id").as_str() == Some("abandon-12"))
        .unwrap();
    let bee = str_of(field(field(vector, "beeWallet"), "address")).to_owned();
    let publishers = field(vector, "publisherKeys")
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let JsValue::Number(index) = field(k, "originIndex") else {
                panic!("an index");
            };
            (*index as u64, str_of(field(k, "address")).to_owned())
        })
        .collect();
    VaultKeys { bee, publishers }
}

struct Vault<'k> {
    keys: &'k VaultKeys,
    unlocked: bool,
}

impl Owners for Vault<'_> {
    fn bee_wallet(&mut self) -> Result<Option<String>, Thrown> {
        Ok(self.unlocked.then(|| self.keys.bee.clone()))
    }

    fn publisher(&mut self, index: f64) -> Result<Option<String>, Thrown> {
        if !self.unlocked {
            return Ok(None);
        }
        let address = self.keys.publishers.get(&(index as u64));
        Ok(Some(
            address.cloned().unwrap_or_else(|| panic!("no key {index}")),
        ))
    }

    fn wallets(&mut self) -> Result<Vec<JsValue>, Thrown> {
        // swarm-world.js: `accounts.list` answers none.
        Ok(Vec::new())
    }
}

fn source_of(options: &JsValue) -> Source {
    match options.get("source").and_then(JsValue::as_str) {
        Some("manifest") => Source::Manifest,
        _ => Source::User,
    }
}

fn play_feeds(case: &JsValue, keys: &VaultKeys) {
    let id = str_of(field(case, "id"));
    let mut dir = Dir::new();
    if let Some(before) = field(case, "before").as_str() {
        dir.insert(feeds::FILE_NAME.to_owned(), before.to_owned());
    }
    if let Some(files) = case.get("before_files") {
        dir.extend(text_map(files));
    }
    let unlocked = case.get("vault").and_then(JsValue::as_str) != Some("locked");
    let mut vault = Vault { keys, unlocked };
    let file = dir.get(feeds::FILE_NAME).map(|t| t.as_bytes().to_vec());
    let loaded = FeedStore::load(file.as_deref(), T0, |name| dir.contains_key(name));
    for write in loaded.writes {
        match write {
            LoadWrite::Backup { name } => {
                let original = dir[feeds::FILE_NAME].clone();
                dir.insert(name, original);
            }
            LoadWrite::Write(text) => {
                dir.insert(feeds::FILE_NAME.to_owned(), text);
            }
        }
    }
    let mut store = loaded.store;
    let index_allocation =
        case.get("deviation").and_then(JsValue::as_str) == Some("index-allocation");
    for (n, op) in field(case, "ops").as_array().unwrap().iter().enumerate() {
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
        let mut write = |changed: Option<String>| {
            if let Some(text) = changed {
                dir.insert(feeds::FILE_NAME.to_owned(), text);
            }
        };
        let got: Result<JsValue, Thrown> = match str_of(field(op, "op")) {
            "createAppScopedIdentity" => store
                .create_app_scoped_identity(&key(), &arg(1), source_of(&arg(1)), T0)
                .map(|c| {
                    write(c.write);
                    c.value
                })
                .map_err(thrown),
            "createAppScopedIdentityAt" => store
                .create_app_scoped_identity_at(&key(), &arg(1), &arg(2), source_of(&arg(2)), T0)
                .map(|c| {
                    write(c.write);
                    c.value
                })
                .map_err(thrown),
            "ensureAntWalletIdentity" => store
                .ensure_ant_wallet_identity(&key(), &arg(1), source_of(&arg(1)), T0)
                .map(|c| {
                    write(c.write);
                    c.value
                })
                .map_err(thrown),
            "activateIdentity" => store
                .activate_identity(&key(), &arg(1), Source::User, T0)
                .map(|c| {
                    write(c.write);
                    c.value
                })
                .map_err(thrown),
            "setFeed" => store
                .set_feed(&key(), &name(), &arg(2), T0)
                .map(|c| {
                    write(c.write);
                    c.value
                })
                .map_err(thrown),
            "updateFeedReference" => store
                .update_feed_reference(&key(), &name(), &arg(2), T0)
                .map(|c| {
                    write(c.write);
                    JsValue::Undefined
                })
                .map_err(thrown),
            "grantFeedAccess" => store
                .grant_feed_access(&key(), source_of(&arg(1)))
                .map(|c| {
                    write(c.write);
                    JsValue::Undefined
                })
                .map_err(thrown),
            "revokeFeedAccess" => store
                .revoke_feed_access(&key(), source_of(&arg(1)))
                .map(|c| {
                    write(c.write);
                    JsValue::Undefined
                })
                .map_err(thrown),
            "setOriginEntry" => store
                .set_origin_entry(&key(), &arg(1), T0)
                .map(|c| {
                    write(c.write);
                    c.value
                })
                .map_err(thrown),
            "allocatePublisherKeyIndex" => store
                .allocate_publisher_key_index()
                .map(|c| {
                    write(c.write);
                    JsValue::Number(c.value)
                })
                .map_err(thrown),
            "getOriginIdentityStateWithOwners" => {
                store.origin_identity_state_with_owners(&key(), &mut vault)
            }
            "previewAppScopedIdentity" => {
                store.preview_app_scoped_identity(&key(), &arg(1), T0, &mut vault)
            }
            "getAllOriginEntries" => store.all_origin_entries().map(JsValue::Array),
            "isIdentitySharedWithOtherOrigins" => Ok(JsValue::Bool(
                store.is_identity_shared_with_other_origins(&key(), &arg(1)),
            )),
            other => panic!("{id}: feed-store operation {other}"),
        };
        let mut want = expected(op);
        if index_allocation {
            want = core_allocation(id, case, want);
        }
        assert_answer(id, n, got, &want);
    }
    let mut want_files = text_map(field(case, "files"));
    if index_allocation {
        let file = want_files.get_mut(feeds::FILE_NAME).unwrap();
        *file = core_allocation_file(file);
    }
    assert_eq!(
        files_with(&dir, |n| n.starts_with("swarm-feeds")),
        want_files,
        "{id}"
    );
}

/// The core's side of `index-allocation`, as the case's `core` states it:
/// the new identity at index 1, where the reference took the counter's 0,
/// which another site holds.
const ALLOCATION_CORE: &str = "allocates index 1: the larger of nextPublisherKeyIndex (0) and one past every stored index (0)";

fn core_allocation(id: &str, case: &JsValue, want: Expected) -> Expected {
    assert_eq!(str_of(field(case, "core")), ALLOCATION_CORE, "{id}");
    let Expected::Value(value) = want else {
        panic!("{id}: the reference's answer is an entry");
    };
    Expected::Value(reindexed(&value))
}

/// An entry with its app-scoped identity 0 moved to index 1.
fn reindexed(entry: &JsValue) -> JsValue {
    let text = entry
        .stringify()
        .replace("app-scoped:0", "app-scoped:1")
        .replace("\"publisherKeyIndex\":0", "\"publisherKeyIndex\":1")
        .replace("App-scoped identity 1", "App-scoped identity 2");
    fc_json::parse(&text).unwrap()
}

/// The file after the core's allocation: the new site's entry reindexed
/// and the counter past index 1; the other site's, which holds 0, as it
/// was.
fn core_allocation_file(file: &str) -> String {
    let mut root = fc_json::parse(file).unwrap();
    assert_eq!(
        root.get("nextPublisherKeyIndex"),
        Some(&JsValue::Number(1.0))
    );
    root.set("nextPublisherKeyIndex", JsValue::Number(2.0));
    let origins = root.get_mut("origins").unwrap();
    let app = origins.get("https://app.example").unwrap().clone();
    origins.set("https://app.example", reindexed(&app));
    root.stringify_pretty()
}

// --- manifests -----------------------------------------------------------------

/// The manifest cases' world: swarm-world.js's grant mirror, the feed
/// store, and the directory.
struct ManifestWorld {
    grants: JsValue,
    feeds: FeedStore,
    dir: Dir,
}

fn grant_record(key: &JsString) -> JsValue {
    let mut auto = JsValue::Object(Vec::new());
    for capability in Capability::ALL {
        auto.set(capability.key(), JsValue::Bool(false));
    }
    let mut record = JsValue::Object(Vec::new());
    record.set("origin", JsValue::String(key.clone()));
    record.set("connectedAt", JsValue::Number(T0 as f64));
    record.set("lastUsed", JsValue::Number(T0 as f64));
    record.set("autoApprove", auto);
    record
}

fn grant_of<'w>(grants: &'w JsValue, key: &JsString) -> Option<&'w JsValue> {
    match grants {
        JsValue::Object(props) => props.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

impl Reads for ManifestWorld {
    fn connected(&self, key: &JsString) -> bool {
        grant_of(&self.grants, key).is_some()
    }

    fn messaging(&self, key: &JsString) -> bool {
        grant_of(&self.grants, key)
            .and_then(|g| g.get("messaging"))
            .is_some_and(JsValue::truthy)
    }

    fn auto_approve(&self, key: &JsString, capability: Capability) -> bool {
        grant_of(&self.grants, key)
            .and_then(|g| g.get("autoApprove"))
            .and_then(|a| a.get(capability.key()))
            == Some(&JsValue::Bool(true))
    }

    fn feeds(&self) -> &FeedStore {
        &self.feeds
    }
}

impl World for ManifestWorld {
    type Error = String;

    fn apply(&mut self, key: &JsString, effect: Effect) -> Result<(), ManifestError<String>> {
        let feed_write = |dir: &mut Dir, write: Option<String>| {
            if let Some(text) = write {
                dir.insert(feeds::FILE_NAME.to_owned(), text);
            }
        };
        let store_error = |e: StoreError| match e {
            StoreError::Thrown(t) => ManifestError::Thrown(t),
            StoreError::Full => ManifestError::Full,
        };
        // swarm-world.js's grantStore: `grant` makes the key's record if it
        // has none; `revoke` changes only a record it has.
        let record = grant_of(&self.grants, key).cloned();
        match effect {
            Effect::Connect => {
                let record = record.unwrap_or_else(|| grant_record(key));
                self.grants.set(key.clone(), record);
            }
            Effect::Disconnect => {
                if let JsValue::Object(props) = &mut self.grants {
                    props.retain(|(k, _)| k != key);
                }
            }
            Effect::Flag {
                capability,
                enabled,
            } => {
                if enabled || record.is_some() {
                    let mut record = record.unwrap_or_else(|| grant_record(key));
                    let mut auto = record.get("autoApprove").cloned().unwrap();
                    auto.set(capability.key(), JsValue::Bool(enabled));
                    record.set("autoApprove", auto);
                    self.grants.set(key.clone(), record);
                }
            }
            Effect::Messaging(enabled) => {
                if enabled || record.is_some() {
                    let mut record = record.unwrap_or_else(|| grant_record(key));
                    record.set("messaging", JsValue::Bool(enabled));
                    self.grants.set(key.clone(), record);
                }
            }
            Effect::FeedGrant(granted) => {
                let changed = if granted {
                    self.feeds.grant_feed_access(key, Source::Manifest)
                } else {
                    self.feeds.revoke_feed_access(key, Source::Manifest)
                }
                .map_err(store_error)?;
                feed_write(&mut self.dir, changed.write);
            }
            Effect::CreateIdentity => {
                let mut options = JsValue::Object(Vec::new());
                options.set("activate", JsValue::Bool(true));
                let changed = self
                    .feeds
                    .create_app_scoped_identity(key, &options, Source::Manifest, T0)
                    .map_err(store_error)?;
                feed_write(&mut self.dir, changed.write);
            }
        }
        Ok(())
    }

    fn save(&mut self, save: &Save) -> Result<(), String> {
        if save.backup
            && let Some(current) = self.dir.get(manifests::FILE_NAME).cloned()
        {
            self.dir.insert(manifests::BACKUP_NAME.to_owned(), current);
        }
        self.dir
            .insert(manifests::FILE_NAME.to_owned(), save.text.clone());
        Ok(())
    }
}

fn manifest_thrown(error: ManifestError<String>) -> Thrown {
    match error {
        ManifestError::Thrown(thrown) => thrown,
        other => panic!("not the reference's refusal: {other:?}"),
    }
}

fn play_manifests(case: &JsValue) {
    let id = str_of(field(case, "id"));
    let site = match field(case, "site") {
        JsValue::String(s) => s.clone(),
        other => panic!("{id}: site {}", short(other)),
    };
    let committed_url = format!("{}/index.html", site.as_str());
    let mut dir = Dir::new();
    if let Some(before) = field(case, "before").as_str() {
        dir.insert(manifests::FILE_NAME.to_owned(), before.to_owned());
    }
    if let Some(files) = case.get("before_files") {
        dir.extend(text_map(files));
    }
    let feeds_text = field(case, "feeds").as_str().map(str::to_owned);
    if let Some(text) = &feeds_text {
        dir.insert(feeds::FILE_NAME.to_owned(), text.clone());
    }
    let loaded = FeedStore::load(feeds_text.as_deref().map(str::as_bytes), T0, |_| false);
    assert!(loaded.writes.is_empty(), "{id}");
    let mut world = ManifestWorld {
        grants: field(case, "grants").clone(),
        feeds: loaded.store,
        dir,
    };
    let mut store = ManifestStore::new();
    let file = world.dir.get(manifests::FILE_NAME).cloned();
    let backup = world.dir.get(manifests::BACKUP_NAME).cloned();
    store
        .load(file.as_deref().map(str::as_bytes), || {
            backup.map(String::into_bytes)
        })
        .unwrap();
    let mut token: Option<String> = None;
    let mut counter = 0u8;
    for (n, step) in field(case, "steps").as_array().unwrap().iter().enumerate() {
        let got: Result<JsValue, Thrown> = match str_of(field(step, "op")) {
            "check" => {
                let eager = field(field(step, "options"), "eager") == &JsValue::Bool(true);
                let manifest = str_of(field(step, "manifest"));
                let status = match step.get("status") {
                    Some(JsValue::Number(s)) => *s as u16,
                    None => 200,
                    Some(other) => panic!("{id}: status {}", short(other)),
                };
                let answer = match store
                    .check(
                        &site,
                        &committed_url,
                        eager,
                        Owner::InProcess,
                        &mut world,
                        T0,
                    )
                    .map_err(manifest_thrown)
                    .unwrap()
                {
                    CheckStep::Done(value) => value,
                    CheckStep::Fetch(fetch) => {
                        assert_eq!(
                            fetch.url,
                            format!("{}/freedom-manifest.json", site.as_str()),
                            "{id}"
                        );
                        let fetched = Fetched::Answered {
                            status,
                            body: manifest.as_bytes(),
                        };
                        store
                            .check_fetched(fetch, fetched, &mut world, T0, || {
                                counter += 1;
                                [counter; 24]
                            })
                            .map_err(manifest_thrown)
                            .unwrap()
                    }
                };
                // The generator writes the token as a placeholder.
                Ok(match answer.get("token").and_then(JsValue::as_str) {
                    Some(t) => {
                        token = Some(t.to_owned());
                        let mut answer = answer.clone();
                        answer.set("token", JsValue::string("(the consent token)"));
                        answer
                    }
                    None => answer,
                })
            }
            "decide" => {
                let outcome = str_of(field(step, "outcome"));
                store
                    .decide(
                        token.as_deref().unwrap(),
                        outcome,
                        Owner::InProcess,
                        &mut world,
                        T0,
                    )
                    .map_err(manifest_thrown)
            }
            "useIndividual" => store
                .use_individual(&site, field(step, "capability"), &mut world, T0)
                .map(JsValue::Bool)
                .map_err(manifest_thrown),
            "disconnect" => store
                .disconnect(&site, &mut world)
                .map(JsValue::Bool)
                .map_err(manifest_thrown),
            "get" => store.get_record(&site, &mut world).map_err(manifest_thrown),
            other => panic!("{id}: manifest operation {other}"),
        };
        assert_answer(id, n, got, &expected(step));
    }
    assert_eq!(
        world.grants.stringify(),
        field(case, "grants_after").stringify(),
        "{id}: grants"
    );
    assert_eq!(
        files_with(&world.dir, |n| n.starts_with("swarm-manifest-grants")
            || n == feeds::FILE_NAME),
        text_map(field(case, "files")),
        "{id}: files"
    );
}

// --- history -------------------------------------------------------------------

/// A directory of its own under the system's temporary directory, removed
/// when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fc-swarm-provider-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
        Cell::Blob(_) => panic!("a BLOB"),
    }
}

/// `getDb()`: WAL, the schema on a new database, then the import, the
/// sweep and the bound.
fn open_history(dir: &Path, now_ms: u64) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(dir.join(history::FILE_NAME)).unwrap();
    let mode: String = conn
        .query_row(
            &format!("PRAGMA journal_mode = {}", history::JOURNAL_MODE),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(mode, "wal");
    let version: i32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    if version < history::SCHEMA_VERSION {
        conn.execute_batch(history::DDL).unwrap();
        conn.pragma_update(None, "user_version", history::SCHEMA_VERSION)
            .unwrap();
    }
    let json = dir.join(history::LEGACY_FILE);
    let migrated = dir.join(format!(
        "{}{}",
        history::LEGACY_FILE,
        history::MIGRATED_SUFFIX
    ));
    let bytes = std::fs::read(&json).ok();
    let legacy = match &bytes {
        None => Legacy::Absent,
        Some(_) if migrated.exists() => Legacy::AlreadyMigrated,
        Some(bytes) => Legacy::File(bytes),
    };
    let opened = history::open(legacy, now_ms);
    conn.execute_batch("BEGIN").unwrap();
    for statement in &opened.import {
        execute(&conn, statement);
    }
    conn.execute_batch("COMMIT").unwrap();
    match opened.legacy {
        LegacyFile::Keep => {}
        LegacyFile::Delete => std::fs::remove_file(&json).unwrap(),
        LegacyFile::Rename => std::fs::rename(&json, &migrated).unwrap(),
    }
    execute(&conn, &opened.sweep);
    execute(&conn, &opened.trim);
    conn
}

fn add_entry(conn: &rusqlite::Connection, entry: &JsValue, now_ms: u64) -> Result<JsValue, Thrown> {
    history::add_entry_checks(entry)?;
    let insert = history::add_entry(entry, now_ms)?;
    execute(conn, &insert);
    let rowid = conn.last_insert_rowid();
    execute(conn, &history::trim(Some(rowid)));
    let rows = query(conn, &history::by_rowid(rowid));
    Ok(history::entry(&rows[0]).unwrap())
}

fn history_op(
    conn: &rusqlite::Connection,
    op: &str,
    args: &[JsValue],
    now_ms: u64,
) -> Result<JsValue, Thrown> {
    let arg = |i: usize| args.get(i).cloned().unwrap_or(JsValue::Undefined);
    match op {
        "addEntry" => add_entry(conn, &arg(0), now_ms),
        "updateEntry" => {
            history::update_entry_checks(&arg(1))?;
            let update = history::update_entry(&arg(0), &arg(1), now_ms)?;
            if execute(conn, &update) == 0 {
                return Ok(JsValue::Null);
            }
            let rows = query(conn, &history::by_id(&arg(0))?);
            Ok(history::entry(&rows[0]).unwrap())
        }
        "getEntries" => Ok(history::entries(&query(conn, &history::get_entries())).unwrap()),
        "removeEntry" => Ok(JsValue::Bool(
            execute(conn, &history::remove_entry(&arg(0))?) > 0,
        )),
        "clearEntries" => {
            execute(conn, &history::clear_entries());
            Ok(JsValue::Undefined)
        }
        other => panic!("publish-history operation {other}"),
    }
}

fn play_history(case: &JsValue) {
    let id = str_of(field(case, "id"));
    let dir = TempDir::new(id);
    if id == "history-10001-rows" {
        return play_history_bound(case, &dir.0);
    }
    if let Some(seed) = case.get("seeded") {
        // A first session at the clock's start, closed with rows left
        // `uploading`.
        let conn = open_history(&dir.0, T0);
        for step in seed.as_array().unwrap() {
            let step = step.as_array().unwrap();
            history_op(&conn, str_of(&step[0]), &step[1..], T0).unwrap();
        }
        drop(conn);
    }
    for (name, text) in text_map(case.get("user_data_before").unwrap_or(&JsValue::Null)) {
        std::fs::write(dir.0.join(name), text).unwrap();
    }
    let now = T0 + 1000;
    let conn = open_history(&dir.0, now);
    for (n, op) in field(case, "ops").as_array().unwrap().iter().enumerate() {
        let args = field(op, "args").as_array().unwrap().to_vec();
        let got = history_op(&conn, str_of(field(op, "op")), &args, now);
        assert_answer(id, n, got, &expected(op));
    }
    let schema: Vec<JsValue> = query(
        &conn,
        &Statement {
            sql: "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            params: Vec::new(),
        },
    )
    .iter()
    .map(|row| {
        let mut out = JsValue::Object(Vec::new());
        for (key, cell) in ["type", "name", "tbl_name", "sql"].iter().zip(row) {
            out.set(*key, cell_value(cell));
        }
        out
    })
    .collect();
    assert_eq!(
        JsValue::Array(schema).stringify(),
        field(case, "schema").stringify(),
        "{id}: schema"
    );
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    let pragmas = field(case, "pragmas");
    assert_eq!(
        Some(&JsValue::Number(version as f64)),
        pragmas.get("user_version"),
        "{id}"
    );
    assert_eq!(
        pragmas.get("journal_mode").and_then(JsValue::as_str),
        Some(mode.as_str()),
        "{id}"
    );
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
        field(case, "rows").stringify(),
        "{id}: rows"
    );
    drop(conn);
    let mut user_data = Dir::new();
    for entry in std::fs::read_dir(&dir.0).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.starts_with(history::LEGACY_FILE) {
            user_data.insert(
                name.clone(),
                std::fs::read_to_string(dir.0.join(&name)).unwrap(),
            );
        }
    }
    assert_eq!(
        user_data,
        text_map(field(case, "user_data")),
        "{id}: user data"
    );
}

/// `history-bound`: 10,001 completed rows; the reference keeps them all,
/// the core the latest 10,000.
fn play_history_bound(case: &JsValue, dir: &Path) {
    let op = &field(case, "ops").as_array().unwrap()[0];
    assert_eq!(str_of(field(op, "op")), "addEntry");
    assert_eq!(field(op, "times"), &JsValue::Number(10001.0));
    let template = field(op, "args").as_array().unwrap()[0].clone();
    assert_eq!(field(&template, "bytesSize").as_str(), Some("<i>"));
    assert_eq!(
        field(case, "rows").stringify(),
        "{\"n\":10001,\"first\":1,\"last\":10001}",
        "the reference keeps every row"
    );
    let conn = open_history(dir, T0);
    for i in 0..10001u32 {
        let mut entry = template.clone();
        entry.set("bytesSize", JsValue::Number(f64::from(i)));
        add_entry(&conn, &entry, T0).unwrap();
    }
    let (n, first, last): (i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*) AS n, MIN(id) AS first, MAX(id) AS last FROM publishes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let got = format!("{{\"n\":{n},\"first\":{first},\"last\":{last}}}");
    assert_eq!(got, field(field(case, "core"), "rows").stringify());
}

/// The bound never takes the row just inserted, even when a clock set back
/// makes it the oldest, and still prefers finished rows as victims.
#[test]
fn history_bound_keeps_the_inserted_row() {
    let entry = |status: &str| {
        let mut e = JsValue::Object(Vec::new());
        e.set("status", JsValue::string(status));
        e
    };
    let ids = |conn: &rusqlite::Connection| -> (i64, i64, i64) {
        conn.query_row(
            "SELECT COUNT(*), MIN(id), MAX(id) FROM publishes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    };
    let has = |conn: &rusqlite::Connection, id: i64| -> bool {
        conn.query_row("SELECT COUNT(*) FROM publishes WHERE id = ?", [id], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
            == 1
    };
    // 10,000 finished rows, then a finished one with the clock set back.
    let dir = TempDir::new("bound-clock-back");
    let conn = open_history(&dir.0, 2_000);
    for _ in 0..10_000 {
        add_entry(&conn, &entry("completed"), 2_000).unwrap();
    }
    let added = add_entry(&conn, &entry("completed"), 1_000).unwrap();
    assert_eq!(field(&added, "id"), &JsValue::Number(10_001.0));
    assert_eq!(ids(&conn), (10_000, 2, 10_001), "the oldest other row went");
    // 10,000 uploading rows, then an uploading one with the clock set back.
    let dir = TempDir::new("bound-clock-back-live");
    let conn = open_history(&dir.0, 2_000);
    for _ in 0..10_000 {
        add_entry(&conn, &entry("uploading"), 2_000).unwrap();
    }
    add_entry(&conn, &entry("uploading"), 1_000).unwrap();
    assert_eq!(ids(&conn), (10_000, 2, 10_001));
    // Mixed: a finished row is the victim before any live one, however new.
    let dir = TempDir::new("bound-mixed");
    let conn = open_history(&dir.0, 2_000);
    for _ in 0..9_999 {
        add_entry(&conn, &entry("uploading"), 2_000).unwrap();
    }
    add_entry(&conn, &entry("failed"), 3_000).unwrap();
    add_entry(&conn, &entry("uploading"), 1_000).unwrap();
    assert!(!has(&conn, 10_000), "the finished row went first");
    assert!(has(&conn, 10_001) && has(&conn, 1));
    assert_eq!(ids(&conn).0, 10_000);
}

/// A BLOB cell, which no writer makes, fails the read that meets it
/// (deviation `history-blobs`), where the reference would answer a Buffer.
#[test]
fn history_blob_cell_fails_the_read() {
    let dir = TempDir::new("blob-cell");
    let conn = open_history(&dir.0, T0);
    let mut e = JsValue::Object(Vec::new());
    e.set("name", JsValue::string("a"));
    add_entry(&conn, &e, T0).unwrap();
    assert!(history::entries(&query(&conn, &history::get_entries())).is_ok());
    conn.execute("UPDATE publishes SET name = X'61'", [])
        .unwrap();
    let rows = query(&conn, &history::get_entries());
    assert_eq!(
        history::entries(&rows),
        Err(history::RowError::Blob("name"))
    );
}
