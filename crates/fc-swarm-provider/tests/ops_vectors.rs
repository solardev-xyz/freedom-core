//! The store ops (design 0015, SWM-4 PR 4) against vectors/swarm.json's
//! `stores`: every case of `feeds` (27), `manifests` (17) and `history`
//! (10) played through `swarm.identities`, `swarm.manifest` and
//! `swarm.history`, each call in its wire form, with the vault's owners
//! and main's manifest fetch answered as asks, over stores the test keeps
//! (SW-1's keeper for the feed store, the manifest store with its files,
//! SQLite through rusqlite for the history).
//!
//! - **feeds:** each operation through the op that runs it: the chrome's
//!   ops (`get-all-origins`, `create-app-scoped-identity`,
//!   `revoke-feed-access`, `get-origin-identities`) and main's
//!   (`ensureAntWalletIdentity`, `createAppScopedIdentityAt`,
//!   `activateIdentity`, `grantFeedAccess`,
//!   `getOriginIdentityStateWithOwners`, `previewAppScopedIdentity`). An
//!   op whose answer is its handler's composition (`create-app-scoped-identity`
//!   answers the state with owners, `revoke-feed-access` `true`) is held to
//!   the store after: the site's entry is the reference's answer, and the
//!   op's answer is the state read from that store. The method machines'
//!   own changes (`setFeed`, `setOriginEntry`, `updateFeedReference`,
//!   `allocatePublisherKeyIndex`, and a manifest's `grantFeedAccess`) go
//!   through the keeper as `FeedChange`s, and their reads (`getFeed`,
//!   `getAllFeeds`, `isIdentitySharedWithOtherOrigins`) are the keeper's
//!   store's.
//! - **manifests:** `check` (its fetch an ask, answered with the case's
//!   manifest), `decide` (with main's `live: true`), `get`,
//!   `use-individual` and `disconnect`; the grants and files after.
//! - **history:** `getEntries`, `clearEntries` and `removeEntry` through
//!   `list`, `clear` and `remove`; the publish machines' `addEntry` and
//!   `updateEntry` as their statements.
//!
//! The deviation cases are held to their `core` answers. Then the ops'
//! own tests: SW-1's hold on the identity changes it covers, a manifest
//! transaction that waits for it whole, the owners, D8's order through the
//! op, and wrong-shape calls refused.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fc_json::index::Index;
use fc_json::{JsString, JsValue};
use fc_swarm_provider::machine::SignKey;
use fc_swarm_provider::machine::keeper::{HoldId, Keeper, Ran, Ticket};
use fc_swarm_provider::ops::{
    self, Call, Caller, Event, Fetch, Grants, Io, Need, Op, Outcome, Refused, Step, Stores, Waiting,
};
use fc_swarm_provider::stores::Thrown;
use fc_swarm_provider::stores::feeds::{self, FeedChange, FeedStore, LoadWrite, Owners, Source};
use fc_swarm_provider::stores::history::{self, Bind, Cell, Legacy, LegacyFile, Row, Statement};
use fc_swarm_provider::stores::manifests::{self, Capability, Effect, ManifestStore, Save};
use fc_swarm_provider::value::Value;

/// The cases' clock; the history runs' is a second later.
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

/// An op's params: `op` and its members, typed.
fn params(op: &str, members: &[(&str, JsValue)]) -> JsValue {
    let mut out = JsValue::Object(Vec::new());
    out.set("op", JsValue::string(op));
    for (name, value) in members {
        out.set(*name, to_typed(value));
    }
    out
}

fn s(text: &str) -> JsValue {
    JsValue::string(text)
}

/// An answer as the reference's own: a value (`undefined` included), or
/// what it throws.
fn outcome_answer(outcome: Outcome) -> Result<JsValue, Thrown> {
    match outcome {
        Outcome::Result(value) => Ok(value_js(&value)),
        Outcome::Thrown(thrown) => Err(thrown),
        Outcome::Cancelled => panic!("cancelled"),
    }
}

/// A typed answer as a JSON value (the stores' answers hold no BigInt or
/// bytes).
fn value_js(value: &Value) -> JsValue {
    match value {
        Value::Undefined => JsValue::Undefined,
        Value::Null => JsValue::Null,
        Value::Bool(b) => JsValue::Bool(*b),
        Value::Number(n) => JsValue::Number(*n),
        Value::String(s) => JsValue::String(s.clone()),
        Value::Array(items) => JsValue::Array(
            items
                .iter()
                .map(|i| value_js(i.as_ref().unwrap()))
                .collect(),
        ),
        Value::Object(members) => JsValue::Object(
            members
                .iter()
                .map(|(k, v)| (k.clone(), value_js(v)))
                .collect(),
        ),
        other => panic!("a store answer holds {other:?}"),
    }
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
            assert_eq!(got.code, want.get("code").map(str_of), "{case} step {step}");
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

fn files_with(dir: &Dir, keep: impl Fn(&str) -> bool) -> Dir {
    dir.iter()
        .filter(|(name, _)| keep(name))
        .map(|(name, text)| (name.clone(), text.clone()))
        .collect()
}

fn core_of(case: &JsValue) -> Option<&JsValue> {
    case.get("core")
        .filter(|core| matches!(core, JsValue::Object(_)))
}

// --- the world -----------------------------------------------------------------

/// keys.json's `abandon-12`: the Bee wallet's and the publisher keys'
/// owners; an index it doesn't list gets an address of its own.
struct VaultKeys {
    bee: [u8; 20],
    publishers: BTreeMap<u32, [u8; 20]>,
}

fn hex20(text: &str) -> [u8; 20] {
    let text = text.strip_prefix("0x").unwrap();
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn vault_keys() -> VaultKeys {
    let text = std::fs::read_to_string(vectors_root().join("keys.json")).unwrap();
    let keys = fc_json::parse(&text).unwrap();
    let vector = field(&keys, "vectors")
        .as_array()
        .unwrap()
        .iter()
        .find(|v| field(v, "id").as_str() == Some("abandon-12"))
        .unwrap();
    let bee = hex20(str_of(field(field(vector, "beeWallet"), "address")));
    let publishers = field(vector, "publisherKeys")
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let JsValue::Number(index) = field(k, "originIndex") else {
                panic!("an index");
            };
            (*index as u32, hex20(str_of(field(k, "address"))))
        })
        .collect();
    VaultKeys { bee, publishers }
}

/// The vault, as the swarm thread asks it: unlocked or locked; with the
/// user's accounts (`accounts.list` answers none in the generator's world).
#[derive(Clone, Copy)]
struct Vault<'k> {
    keys: &'k VaultKeys,
    unlocked: bool,
}

impl Vault<'_> {
    fn owner(&self, key: SignKey) -> Option<[u8; 20]> {
        if !self.unlocked {
            return None;
        }
        Some(match key {
            SignKey::BeeWallet => self.keys.bee,
            SignKey::Publisher(index) => self
                .keys
                .publishers
                .get(&index)
                .copied()
                .unwrap_or([0xa0 ^ (index as u8); 20]),
        })
    }

    fn event(&self, need: &Need) -> Event {
        match need {
            Need::Owner(key) => Event::Owner(Ok(self.owner(*key))),
            Need::Accounts => Event::Accounts(Ok(Vec::new())),
            Need::Manifest { .. } => panic!("a fetch asked of the vault"),
        }
    }
}

/// The same vault, as the store's codec reads it directly.
impl Owners for Vault<'_> {
    fn bee_wallet(&mut self) -> Result<Option<String>, Thrown> {
        Ok(self
            .owner(SignKey::BeeWallet)
            .map(|a| fc_evm::checksum_address(&a)))
    }

    fn publisher(&mut self, index: f64) -> Result<Option<String>, Thrown> {
        Ok(self
            .owner(SignKey::Publisher(index as u32))
            .map(|a| fc_evm::checksum_address(&a)))
    }

    fn wallets(&mut self) -> Result<Vec<JsValue>, Thrown> {
        Ok(Vec::new())
    }
}

/// The Swarm grants' mirror (swarm-world.js's `grantStore`): `grant` makes
/// the key's record if it has none; `revoke` changes only a record it has.
struct GrantMirror {
    grants: JsValue,
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

impl GrantMirror {
    fn of(&self, key: &JsString) -> Option<&JsValue> {
        match &self.grants {
            JsValue::Object(props) => props.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

impl Grants for GrantMirror {
    fn connected(&self, key: &JsString) -> bool {
        self.of(key).is_some()
    }

    fn messaging(&self, key: &JsString) -> bool {
        self.of(key)
            .and_then(|g| g.get("messaging"))
            .is_some_and(JsValue::truthy)
    }

    fn auto_approve(&self, key: &JsString, capability: Capability) -> bool {
        self.of(key)
            .and_then(|g| g.get("autoApprove"))
            .and_then(|a| a.get(capability.key()))
            == Some(&JsValue::Bool(true))
    }

    fn apply(&mut self, key: &JsString, effect: Effect) -> Result<(), JsString> {
        let record = self.of(key).cloned();
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
            Effect::FeedGrant(_) | Effect::CreateIdentity => {
                panic!("a feed-store effect reached the grants")
            }
        }
        Ok(())
    }
}

/// The files, the history's database and the token's randomness.
struct Disk {
    dir: Dir,
    db: Option<rusqlite::Connection>,
    random: u8,
    /// A write that fails, by file name.
    fail: Option<&'static str>,
}

impl Disk {
    fn new(dir: Dir) -> Disk {
        Disk {
            dir,
            db: None,
            random: 0,
            fail: None,
        }
    }
}

impl Io for Disk {
    fn write_feeds(&mut self, text: &str) -> Result<(), JsString> {
        if self.fail == Some(feeds::FILE_NAME) {
            return Err(JsString::from("ENOSPC: no space left on device, write"));
        }
        self.dir
            .insert(feeds::FILE_NAME.to_owned(), text.to_owned());
        Ok(())
    }

    fn read_manifests(&mut self) -> Option<Vec<u8>> {
        self.dir
            .get(manifests::FILE_NAME)
            .map(|t| t.clone().into_bytes())
    }

    fn read_manifests_backup(&mut self) -> Option<Vec<u8>> {
        self.dir
            .get(manifests::BACKUP_NAME)
            .map(|t| t.clone().into_bytes())
    }

    fn save_manifests(&mut self, save: &Save) -> Result<(), JsString> {
        if self.fail == Some(manifests::FILE_NAME) {
            return Err(JsString::from("ENOSPC: no space left on device, write"));
        }
        if save.backup
            && let Some(current) = self.dir.get(manifests::FILE_NAME).cloned()
        {
            self.dir.insert(manifests::BACKUP_NAME.to_owned(), current);
        }
        self.dir
            .insert(manifests::FILE_NAME.to_owned(), save.text.clone());
        Ok(())
    }

    fn random(&mut self) -> [u8; 24] {
        self.random += 1;
        [self.random; 24]
    }

    fn query(&mut self, statement: &Statement) -> Result<Vec<Row>, JsString> {
        Ok(query(self.db.as_ref().unwrap(), statement))
    }

    fn run(&mut self, statement: &Statement) -> Result<usize, JsString> {
        Ok(execute(self.db.as_ref().unwrap(), statement))
    }
}

/// The swarm thread's stores, as the test keeps them.
struct World {
    keeper: Keeper,
    manifests: ManifestStore,
    grants: GrantMirror,
    disk: Disk,
    tickets: u64,
}

impl World {
    fn new(feeds: FeedStore, grants: JsValue, dir: Dir) -> World {
        World {
            keeper: Keeper::new(feeds),
            manifests: ManifestStore::new(),
            grants: GrantMirror { grants },
            disk: Disk::new(dir),
            tickets: 0,
        }
    }

    fn stores(&mut self, now_ms: u64) -> Stores<'_> {
        Stores {
            now_ms,
            keeper: &mut self.keeper,
            manifests: &mut self.manifests,
            grants: &mut self.grants,
            io: &mut self.disk,
        }
    }

    fn op(&mut self, method: &str, params: &JsValue, caller: Caller) -> Op {
        self.tickets += 1;
        let call = Call::parse(method, params, caller)
            .unwrap_or_else(|e| panic!("{method} {}: {e}", short(params)));
        Op::new(call, Ticket(self.tickets))
    }

    /// An op played to its end: owners from `vault`, a manifest fetch from
    /// `fetch`. Every ask is checked as main and the vault would read it.
    fn play(
        &mut self,
        method: &str,
        params: &JsValue,
        caller: Caller,
        vault: Vault<'_>,
        mut fetch: impl FnMut(&str) -> Fetch,
    ) -> Outcome {
        let mut op = self.op(method, params, caller);
        let mut step = op.start(&mut self.stores(T0));
        loop {
            match step {
                Step::Done(outcome) => return outcome,
                Step::Asks(asks) => {
                    assert!(!asks.is_empty());
                    let mut last = Step::Ended;
                    for ask in asks {
                        let event = match &ask.need {
                            Need::Manifest { url } => Event::Manifest(fetch(url)),
                            need => vault.event(need),
                        };
                        last = op.answer(ask.id, event, &mut self.stores(T0));
                        if !matches!(last, Step::Wait(Waiting::Answers)) {
                            break;
                        }
                    }
                    step = last;
                }
                other => panic!("{method} {}: {other:?}", short(params)),
            }
        }
    }

    /// A method machine's feed-store change, through the keeper.
    fn feed_change(&mut self, change: FeedChange) -> Result<JsValue, Thrown> {
        self.tickets += 1;
        let disk = &mut self.disk;
        match self
            .keeper
            .change(Ticket(self.tickets), change, T0, &mut |t: &str| {
                disk.write_feeds(t)
            }) {
            Ran::Applied(Ok(answer)) => Ok(answer.value),
            Ran::Applied(Err(error)) => Err(match error {
                fc_swarm_provider::machine::keeper::ChangeError::Store(
                    fc_swarm_provider::stores::StoreError::Thrown(t),
                ) => t,
                other => panic!("{other:?}"),
            }),
            Ran::Deferred => panic!("deferred with no hold"),
        }
    }
}

fn no_fetch(url: &str) -> Fetch {
    panic!("a fetch of {url}")
}

// --- the cases -------------------------------------------------------------------

#[test]
fn every_stores_case_through_the_ops() {
    let cases = stores_section();
    let keys = vault_keys();
    let mut played: BTreeMap<String, usize> = BTreeMap::new();
    for case in &cases {
        let kind = str_of(field(case, "kind"));
        match kind {
            "feeds" => play_feeds(case, &keys),
            "manifests" => play_manifests(case, &keys),
            "history" => play_history(case),
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

fn play_feeds(case: &JsValue, keys: &VaultKeys) {
    let id = str_of(field(case, "id"));
    let mut dir = Dir::new();
    if let Some(before) = field(case, "before").as_str() {
        dir.insert(feeds::FILE_NAME.to_owned(), before.to_owned());
    }
    if let Some(files) = case.get("before_files") {
        dir.extend(text_map(files));
    }
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
    if let Some(before) = case.get("core_before") {
        assert_eq!(
            loaded.store.text().unwrap(),
            str_of(before),
            "{id}: core_before"
        );
    }
    let mut world = World::new(loaded.store, JsValue::Object(Vec::new()), dir);
    let vault = Vault {
        keys,
        unlocked: case.get("vault").and_then(JsValue::as_str) != Some("locked"),
    };
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
        let shell = |world: &mut World, op: &str, members: &[(&str, JsValue)]| {
            outcome_answer(world.play(
                ops::IDENTITIES,
                &params(op, members),
                Caller::Shell,
                vault,
                no_fetch,
            ))
        };
        let chrome = |world: &mut World, op: &str, members: &[(&str, JsValue)]| {
            outcome_answer(world.play(
                ops::IDENTITIES,
                &params(op, members),
                Caller::Chrome,
                vault,
                no_fetch,
            ))
        };
        let got: Result<JsValue, Thrown> = match str_of(field(op, "op")) {
            "getAllOriginEntries" => chrome(&mut world, "get-all-origins", &[]),
            "getOriginIdentityStateWithOwners" => {
                let got = shell(
                    &mut world,
                    "getOriginIdentityStateWithOwners",
                    &[("key", arg(0))],
                );
                // The chrome's handler answers the same.
                let again = chrome(&mut world, "get-origin-identities", &[("origin", arg(0))]);
                assert_eq!(
                    again.as_ref().map(JsValue::stringify),
                    got.as_ref().map(JsValue::stringify),
                    "{id} step {n}: the chrome's"
                );
                got
            }
            "previewAppScopedIdentity" => shell(
                &mut world,
                "previewAppScopedIdentity",
                &[("key", arg(0)), ("options", arg(1))],
            ),
            "createAppScopedIdentityAt" => shell(
                &mut world,
                "createAppScopedIdentityAt",
                &[("key", arg(0)), ("index", arg(1)), ("options", arg(2))],
            ),
            "ensureAntWalletIdentity" => shell(
                &mut world,
                "ensureAntWalletIdentity",
                &[("key", arg(0)), ("options", arg(1))],
            ),
            "activateIdentity" => shell(
                &mut world,
                "activateIdentity",
                &[("key", arg(0)), ("identity_id", arg(1))],
            ),
            "grantFeedAccess"
                if arg(1).get("source").and_then(JsValue::as_str) == Some("manifest") =>
            {
                // A manifest's projection, which the manifest ops make
                // through the keeper.
                world.feed_change(FeedChange::GrantFeedAccess {
                    key: key(),
                    source: Source::Manifest,
                })
            }
            "grantFeedAccess" => {
                assert!(arg(1).get("source").is_none(), "{id}");
                shell(&mut world, "grantFeedAccess", &[("key", arg(0))])
            }
            "createAppScopedIdentity" => {
                assert!(arg(1).get("source").is_none(), "{id}");
                // The chrome's handler: the change, then the state with
                // owners. The site's entry after is the reference's answer.
                let got = chrome(
                    &mut world,
                    "create-app-scoped-identity",
                    &[("origin", arg(0)), ("options", arg(1))],
                );
                got.map(|state| {
                    let mut owners = vault;
                    let read = world
                        .keeper
                        .store()
                        .origin_identity_state_with_owners(&key(), &mut owners)
                        .unwrap();
                    assert_eq!(state.stringify(), read.stringify(), "{id} step {n}: state");
                    world.keeper.store().origin_entry(&key()).unwrap()
                })
            }
            "revokeFeedAccess" => {
                assert!(arg(1).get("source").is_none(), "{id}");
                chrome(&mut world, "revoke-feed-access", &[("origin", arg(0))]).map(|answer| {
                    assert_eq!(answer, JsValue::Bool(true), "{id} step {n}");
                    JsValue::Undefined
                })
            }
            "setFeed" => world.feed_change(FeedChange::SetFeed {
                key: key(),
                name: name(),
                data: arg(2),
            }),
            "updateFeedReference" => world.feed_change(FeedChange::UpdateFeedReference {
                key: key(),
                name: name(),
                reference: arg(2),
            }),
            "setOriginEntry" => world.feed_change(FeedChange::SetOriginEntry {
                key: key(),
                data: arg(1),
            }),
            "allocatePublisherKeyIndex" => world.feed_change(FeedChange::AllocatePublisherKeyIndex),
            "getFeed" => Ok(world
                .keeper
                .store()
                .feed(&key(), &name())
                .unwrap_or(JsValue::Null)),
            "getAllFeeds" => Ok(world.keeper.store().all_feeds(&key())),
            "isIdentitySharedWithOtherOrigins" => Ok(JsValue::Bool(
                world
                    .keeper
                    .store()
                    .is_identity_shared_with_other_origins(&key(), &arg(1)),
            )),
            other => panic!("{id}: feed-store operation {other}"),
        };
        assert_answer(id, n, got, &want);
    }
    let mut want_files = text_map(field(core.unwrap_or(case), "files"));
    if allocation {
        let file = want_files.get_mut(feeds::FILE_NAME).unwrap();
        *file = core_allocation_file(file);
    }
    assert_eq!(
        files_with(&world.disk.dir, |n| n.starts_with("swarm-feeds")),
        want_files,
        "{id}"
    );
}

fn play_manifests(case: &JsValue, keys: &VaultKeys) {
    let id = str_of(field(case, "id"));
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
    let feeds_text = field(case, "feeds").as_str().map(str::to_owned);
    if let Some(text) = &feeds_text {
        dir.insert(feeds::FILE_NAME.to_owned(), text.clone());
    }
    let loaded = FeedStore::load(feeds_text.as_deref().map(str::as_bytes), T0, |_| false);
    assert!(loaded.writes.is_empty(), "{id}");
    let before = dir.clone();
    let mut world = World::new(loaded.store, field(case, "grants").clone(), dir);
    let vault = Vault {
        keys,
        unlocked: true,
    };
    let core = core_of(case);
    let steps = field(case, "steps").as_array().unwrap();
    // store-shapes: neither the file nor its .bak copy is read, so every
    // op fails, and nothing is written.
    if let Some(load) = core.and_then(|core| core.get("load")) {
        assert_eq!(str_of(load), "unreadable", "{id}");
        for (n, step) in steps.iter().enumerate() {
            let op = match str_of(field(step, "op")) {
                "useIndividual" => params(
                    "use-individual",
                    &[
                        ("origin", site.clone()),
                        ("capability", field(step, "capability").clone()),
                    ],
                ),
                "get" => params("get", &[("origin", site.clone())]),
                other => panic!("{id}: {other}"),
            };
            let got = world.play(ops::MANIFEST, &op, Caller::Shell, vault, no_fetch);
            assert_eq!(
                got,
                Outcome::Thrown(Thrown {
                    name: fc_swarm_provider::stores::ErrorName::Error,
                    message: "swarm-manifest-grants.json and its backup are unreadable".to_owned(),
                    code: None,
                }),
                "{id} step {n}"
            );
        }
        assert!(!world.manifests.is_loaded(), "{id}");
        assert_eq!(world.disk.dir, before, "{id}: nothing written");
        return;
    }
    let core_steps = core.map(|core| field(core, "steps").as_array().unwrap());
    let mut token: Option<JsValue> = None;
    for (n, step) in steps.iter().enumerate() {
        let got = match str_of(field(step, "op")) {
            "check" => {
                let eager = field(field(step, "options"), "eager") == &JsValue::Bool(true);
                let manifest = str_of(field(step, "manifest")).as_bytes().to_vec();
                let status = match step.get("status") {
                    Some(JsValue::Number(s)) => *s as u16,
                    None => 200,
                    Some(other) => panic!("{id}: status {}", short(other)),
                };
                let mut fetched = 0;
                let call = params(
                    "check",
                    &[
                        ("key", site.clone()),
                        ("url", url.clone()),
                        ("eager", JsValue::Bool(eager)),
                    ],
                );
                let answer = world.play(ops::MANIFEST, &call, Caller::Shell, vault, |asked| {
                    assert_eq!(asked, format!("{site_text}/freedom-manifest.json"), "{id}");
                    fetched += 1;
                    Fetch::Answered {
                        status,
                        body: manifest.clone(),
                    }
                });
                assert!(fetched <= 1, "{id}");
                outcome_answer(answer).map(|answer| match answer.get("token") {
                    Some(t) => {
                        token = Some(t.clone());
                        let mut answer = answer.clone();
                        answer.set("token", JsValue::string("(the consent token)"));
                        answer
                    }
                    None => answer,
                })
            }
            "decide" => {
                let call = params(
                    "decide",
                    &[
                        ("key", site.clone()),
                        ("token", token.clone().unwrap()),
                        ("outcome", field(step, "outcome").clone()),
                        ("live", JsValue::Bool(true)),
                    ],
                );
                outcome_answer(world.play(ops::MANIFEST, &call, Caller::Shell, vault, no_fetch))
            }
            "useIndividual" => outcome_answer(world.play(
                ops::MANIFEST,
                &params(
                    "use-individual",
                    &[
                        ("origin", site.clone()),
                        ("capability", field(step, "capability").clone()),
                    ],
                ),
                Caller::Shell,
                vault,
                no_fetch,
            )),
            "disconnect" => outcome_answer(world.play(
                ops::MANIFEST,
                &params("disconnect", &[("origin", site.clone())]),
                Caller::Shell,
                vault,
                no_fetch,
            )),
            "get" => outcome_answer(world.play(
                ops::MANIFEST,
                &params("get", &[("origin", site.clone())]),
                Caller::Shell,
                vault,
                no_fetch,
            )),
            other => panic!("{id}: manifest operation {other}"),
        };
        let want = match core_steps {
            Some(answers) => expected(&answers[n]),
            None => expected(step),
        };
        assert_answer(id, n, got, &want);
    }
    let side = core.unwrap_or(case);
    assert_eq!(
        world.grants.grants.stringify(),
        field(side, "grants_after").stringify(),
        "{id}: grants"
    );
    assert_eq!(
        files_with(&world.disk.dir, |n| n.starts_with("swarm-manifest-grants")
            || n == feeds::FILE_NAME),
        text_map(field(side, "files")),
        "{id}: files"
    );
}

// --- history -------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "fc-swarm-provider-ops-{}-{name}",
            std::process::id()
        ));
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

/// `getDb()`: WAL, the schema on a new database, then the import, the
/// sweep and the bound (PR 7's open, run here as the vectors' sessions
/// need it).
fn open_history(dir: &Path, now_ms: u64) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(dir.join(history::FILE_NAME)).unwrap();
    let _: String = conn
        .query_row(
            &format!("PRAGMA journal_mode = {}", history::JOURNAL_MODE),
            [],
            |r| r.get(0),
        )
        .unwrap();
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

/// The publish machines' `addEntry`: the insert, the bound, the row back.
fn add_entry(conn: &rusqlite::Connection, entry: &JsValue, now_ms: u64) -> Result<JsValue, Thrown> {
    history::add_entry_checks(entry)?;
    execute(conn, &history::add_entry(entry, now_ms)?);
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
) -> Result<JsValue, Thrown> {
    history::update_entry_checks(updates)?;
    if execute(conn, &history::update_entry(id, updates, now_ms)?) == 0 {
        return Ok(JsValue::Null);
    }
    Ok(history::entry(&query(conn, &history::by_id(id)?)[0]).unwrap())
}

/// A history op through `swarm.history`.
fn history_op(world: &mut World, op: &str, members: &[(&str, JsValue)]) -> Outcome {
    let vault_keys = VaultKeys {
        bee: [0; 20],
        publishers: BTreeMap::new(),
    };
    let vault = Vault {
        keys: &vault_keys,
        unlocked: false,
    };
    world.play(
        ops::HISTORY,
        &params(op, members),
        Caller::Chrome,
        vault,
        no_fetch,
    )
}

fn play_history(case: &JsValue) {
    let id = str_of(field(case, "id"));
    let dir = TempDir::new(id);
    let mut world = World::new(FeedStore::empty(), JsValue::Null, Dir::new());
    if id == "history-10001-rows" {
        let op = &field(case, "ops").as_array().unwrap()[0];
        assert_eq!(field(op, "times"), &JsValue::Number(10001.0));
        let template = field(op, "args").as_array().unwrap()[0].clone();
        world.disk.db = Some(open_history(&dir.0, T0));
        for i in 0..10001u32 {
            let mut entry = template.clone();
            entry.set("bytesSize", JsValue::Number(f64::from(i)));
            add_entry(world.disk.db.as_ref().unwrap(), &entry, T0).unwrap();
        }
        // The core keeps the latest 10,000, which `list` answers.
        let Outcome::Result(Value::Array(entries)) = history_op(&mut world, "list", &[]) else {
            panic!("{id}: list");
        };
        assert_eq!(entries.len(), 10_000);
        let ids: Vec<f64> = entries
            .iter()
            .map(|e| match value_js(e.as_ref().unwrap()).get("id") {
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
        let conn = open_history(&dir.0, T0);
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
    for (name, text) in text_map(case.get("user_data_before").unwrap_or(&JsValue::Null)) {
        std::fs::write(dir.0.join(name), text).unwrap();
    }
    let now = T0 + 1000;
    world.disk.db = Some(open_history(&dir.0, now));
    let core = core_of(case);
    let core_ops = core.map(|core| field(core, "ops").as_array().unwrap());
    for (n, op) in field(case, "ops").as_array().unwrap().iter().enumerate() {
        let args = field(op, "args").as_array().unwrap().to_vec();
        let arg = |i: usize| args.get(i).cloned().unwrap_or(JsValue::Undefined);
        let want = core_ops.map_or(op, |answers| &answers[n]);
        let result = |value: JsValue| Outcome::Result(Value::from_js(&value));
        let got = match str_of(field(op, "op")) {
            "addEntry" => add_entry(world.disk.db.as_ref().unwrap(), &arg(0), now).map(result),
            "updateEntry" => {
                update_entry(world.disk.db.as_ref().unwrap(), &arg(0), &arg(1), now).map(result)
            }
            "getEntries" => Ok(history_op(&mut world, "list", &[])),
            "clearEntries" => Ok(history_op(&mut world, "clear", &[])),
            "removeEntry" => Ok(history_op(&mut world, "remove", &[("id", arg(0))])),
            other => panic!("{id}: history operation {other}"),
        };
        let got = match got {
            Ok(outcome) => outcome,
            Err(thrown) => Outcome::Thrown(thrown),
        };
        if let Some(refused) = want.get("refused") {
            assert_eq!(str_of(field(refused, "reason")), "blob", "{id} step {n}");
            let column = str_of(field(refused, "column"));
            let Outcome::Thrown(thrown) = got else {
                panic!("{id} step {n}: {got:?}, want the BLOB refused");
            };
            assert_eq!(
                thrown.code,
                Some(ops::history::HISTORY_BLOB),
                "{id} step {n}"
            );
            assert_eq!(
                thrown.message,
                format!("publish-history.sqlite holds a BLOB in column {column}"),
                "{id} step {n}"
            );
            continue;
        }
        assert_answer(id, n, outcome_answer(got), &expected(want));
    }
    let rows: Vec<JsValue> = query(
        world.disk.db.as_ref().unwrap(),
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
}

// --- the ops' own tests ----------------------------------------------------------

fn js(text: &str) -> JsValue {
    fc_json::parse(text).unwrap()
}

fn key(text: &str) -> JsString {
    JsString::from(text)
}

/// Site `a` on app-scoped index 0 with its feed grant, holding the Bee
/// wallet too and app-scoped index 1; site `b` on the Bee wallet.
const HELD_FEEDS: &str = r#"{"version":2,"nextPublisherKeyIndex":2,"origins":{"a":{"activeIdentityId":"app-scoped:0","identities":{"app-scoped:0":{"id":"app-scoped:0","mode":"app-scoped","publisherKeyIndex":0,"walletIndex":null,"label":"A","createdAt":1,"lastUsedAt":null},"app-scoped:1":{"id":"app-scoped:1","mode":"app-scoped","publisherKeyIndex":1,"walletIndex":null,"label":"B","createdAt":2,"lastUsedAt":null},"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee","createdAt":3,"lastUsedAt":null}},"feedGranted":true,"grantedAt":1,"feeds":{}},"b":{"activeIdentityId":"bee-wallet","identities":{"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee","createdAt":1,"lastUsedAt":null}},"feedGranted":true,"grantedAt":1,"feeds":{}}}}"#;

fn feeds_world(text: &str, grants: &str, manifests: Option<&str>) -> World {
    let store = FeedStore::load(Some(text.as_bytes()), T0, |_| false).store;
    let mut dir = Dir::new();
    dir.insert(feeds::FILE_NAME.to_owned(), text.to_owned());
    if let Some(manifests) = manifests {
        dir.insert(manifests::FILE_NAME.to_owned(), manifests.to_owned());
    }
    World::new(store, js(grants), dir)
}

fn active_id(world: &World, site: &str) -> JsValue {
    world
        .keeper
        .store()
        .active_origin_identity(&key(site))
        .and_then(|i| i.get("id").cloned())
        .unwrap_or(JsValue::Null)
}

/// Asks answered by `vault` until the op is done.
fn finish(world: &mut World, op: &mut Op, mut step: Step, vault: Vault<'_>) -> Outcome {
    loop {
        match step {
            Step::Done(outcome) => return outcome,
            Step::Asks(asks) => {
                let mut last = Step::Ended;
                for ask in asks {
                    last = op.answer(ask.id, vault.event(&ask.need), &mut world.stores(T0));
                }
                step = last;
            }
            other => panic!("{other:?}"),
        }
    }
}

/// SW-1's hold (design 0015, "SW-1 in the core"): from the re-check until
/// the vault answers, the site's activations and its revoke wait; every
/// other change goes on. Once the hold ends they are made in order, and
/// each op answers then.
#[test]
fn sw1_holds_the_identity_changes_it_covers() {
    let keys = vault_keys();
    let vault = Vault {
        keys: &keys,
        unlocked: true,
    };
    let mut world = feeds_world(HELD_FEEDS, "{}", None);
    world.keeper.hold(HoldId(1), key("a"));
    let written = world.disk.dir[feeds::FILE_NAME].clone();
    let mut held = Vec::new();
    for (caller, op) in [
        // The chrome's switch, main's prompt switch, an ensure that
        // activates, the chrome's revoke.
        (
            Caller::Chrome,
            params(
                "activate-feed-identity",
                &[("origin", s("a")), ("identity_id", s("app-scoped:1"))],
            ),
        ),
        (
            Caller::Shell,
            params(
                "activateIdentity",
                &[("key", s("a")), ("identity_id", s("bee-wallet"))],
            ),
        ),
        (
            Caller::Shell,
            params(
                "ensureAntWalletIdentity",
                &[("key", s("a")), ("options", js(r#"{"activate":true}"#))],
            ),
        ),
        (
            Caller::Chrome,
            params("revoke-feed-access", &[("origin", s("a"))]),
        ),
    ] {
        let mut op = world.op(ops::IDENTITIES, &op, caller);
        let step = op.start(&mut world.stores(T0));
        assert_eq!(step, Step::Wait(Waiting::Change));
        held.push(op);
    }
    assert_eq!(world.keeper.deferred(), 4);
    assert_eq!(world.disk.dir[feeds::FILE_NAME], written, "nothing written");
    assert_eq!(active_id(&world, "a"), s("app-scoped:0"));
    // These go on: an ensure that doesn't activate, a create that doesn't,
    // a grant, and another site's revoke.
    for (caller, op) in [
        (
            Caller::Chrome,
            params("ensure-ant-wallet-identity", &[("origin", s("a"))]),
        ),
        (
            Caller::Chrome,
            params(
                "create-app-scoped-identity",
                &[("origin", s("a")), ("options", js(r#"{"activate":false}"#))],
            ),
        ),
        (Caller::Shell, params("grantFeedAccess", &[("key", s("a"))])),
        (
            Caller::Chrome,
            params("revoke-feed-access", &[("origin", s("b"))]),
        ),
    ] {
        let outcome = world.play(ops::IDENTITIES, &op, caller, vault, no_fetch);
        assert!(matches!(outcome, Outcome::Result(_)), "{outcome:?}");
    }
    assert_eq!(active_id(&world, "a"), s("app-scoped:0"));
    assert!(!world.keeper.store().has_feed_grant(&key("b")));
    // The hold ends: the four, in order, each answered under its ticket.
    let disk = &mut world.disk;
    let answers = world
        .keeper
        .release(HoldId(1), T0, &mut |t: &str| disk.write_feeds(t));
    assert_eq!(answers.len(), 4);
    let mut outcomes = Vec::new();
    for (ticket, answer) in answers {
        let at = held.iter().position(|op| op.ticket() == ticket).unwrap();
        let mut op = held.remove(at);
        let step = op.changed(answer, &mut world.stores(T0));
        outcomes.push(finish(&mut world, &mut op, step, vault));
    }
    // The chrome's switch answers the state with owners as it stands when
    // its owners arrive: after all four, which the hold's end made at
    // once. Main's switch and the ensure answer their entries as each was
    // made; the revoke `true`.
    let state = outcome_answer(outcomes.remove(0)).unwrap();
    assert_eq!(state.get("activeIdentityId"), Some(&s("bee-wallet")));
    assert_eq!(state.get("feedGranted"), Some(&JsValue::Bool(false)));
    assert_eq!(
        state.get("identities").unwrap().as_array().unwrap().len(),
        4,
        "the identity made while it waited is listed"
    );
    let entry = outcome_answer(outcomes.remove(0)).unwrap();
    assert_eq!(entry.get("activeIdentityId"), Some(&s("bee-wallet")));
    assert_eq!(entry.get("feedGranted"), Some(&JsValue::Bool(true)));
    let entry = outcome_answer(outcomes.remove(0)).unwrap();
    assert_eq!(entry.get("identityMode"), Some(&s("bee-wallet")));
    assert_eq!(outcome_answer(outcomes.remove(0)), Ok(JsValue::Bool(true)));
    assert_eq!(active_id(&world, "a"), s("bee-wallet"));
    assert!(!world.keeper.store().has_feed_grant(&key("a")));
    assert_eq!(
        world.disk.dir[feeds::FILE_NAME],
        world.keeper.store().text().unwrap()
    );
}

/// An op cancelled while its change waits: the change is still made at
/// the hold's end (a write can't be called back), and its answer dropped.
#[test]
fn a_cancelled_op_leaves_its_change_to_the_keeper() {
    let mut world = feeds_world(HELD_FEEDS, "{}", None);
    world.keeper.hold(HoldId(1), key("a"));
    let mut op = world.op(
        ops::IDENTITIES,
        &params("revoke-feed-access", &[("origin", s("a"))]),
        Caller::Chrome,
    );
    assert_eq!(op.start(&mut world.stores(T0)), Step::Wait(Waiting::Change));
    assert_eq!(op.cancel(), Step::Done(Outcome::Cancelled));
    let disk = &mut world.disk;
    let answers = world
        .keeper
        .release(HoldId(1), T0, &mut |t: &str| disk.write_feeds(t));
    assert_eq!(answers.len(), 1);
    let (_, answer) = answers.into_iter().next().unwrap();
    assert_eq!(op.changed(answer, &mut world.stores(T0)), Step::Ended);
    assert!(!world.keeper.store().has_feed_grant(&key("a")));
}

/// A record managing site `a`'s connection and feed grant through its
/// `feeds` capability.
const MANAGED: &str = r#"{"version":1,"records":{"a":{"managed":{"connection":["feeds"],"feedGrant":["feeds"]},"acknowledged":{"feeds":{"decision":"managed","source":"sheet","decidedAt":1}},"revision":1}}}"#;

/// A manifest transaction that would revoke a held site's feed grant waits
/// whole for the hold's end, with nothing written; one that doesn't goes
/// on.
#[test]
fn a_manifest_revoke_of_a_held_grant_waits_whole() {
    let keys = vault_keys();
    let vault = Vault {
        keys: &keys,
        unlocked: true,
    };
    let grants = r#"{"a":{"origin":"a","connectedAt":1,"lastUsed":1,"autoApprove":{"publish":false,"feeds":false,"signing":false,"messaging":false}}}"#;
    let mut world = feeds_world(HELD_FEEDS, grants, Some(MANAGED));
    world.keeper.hold(HoldId(7), key("a"));
    let before = world.disk.dir.clone();
    let mut op = world.op(
        ops::MANIFEST,
        &params("disconnect", &[("origin", s("a"))]),
        Caller::Shell,
    );
    assert_eq!(op.start(&mut world.stores(T0)), Step::Wait(Waiting::Hold));
    assert_eq!(
        world.disk.dir, before,
        "nothing written, not even the journal"
    );
    assert!(world.grants.connected(&key("a")));
    // Still held: tried again, it waits again.
    assert_eq!(op.retry(&mut world.stores(T0)), Step::Wait(Waiting::Hold));
    // A read, and a capability the record doesn't hold, go on.
    let record = world.play(
        ops::MANIFEST,
        &params("get", &[("origin", s("a"))]),
        Caller::Shell,
        vault,
        no_fetch,
    );
    assert!(matches!(record, Outcome::Result(Value::Object(_))));
    let handed = world.play(
        ops::MANIFEST,
        &params(
            "use-individual",
            &[("origin", s("a")), ("capability", s("publish"))],
        ),
        Caller::Shell,
        vault,
        no_fetch,
    );
    assert_eq!(handed, Outcome::Result(Value::Bool(false)));
    // So does the disconnect of a site no hold covers.
    let disk = &mut world.disk;
    assert!(
        world
            .keeper
            .release(HoldId(7), T0, &mut |t: &str| disk.write_feeds(t))
            .is_empty()
    );
    let step = op.retry(&mut world.stores(T0));
    assert_eq!(step, Step::Done(Outcome::Result(Value::Bool(true))));
    assert!(!world.grants.connected(&key("a")));
    assert!(!world.keeper.store().has_feed_grant(&key("a")));
    let manifests = js(&world.disk.dir[manifests::FILE_NAME]);
    assert_eq!(manifests.get("records"), Some(&js("{}")));
}

/// A check whose manifest is gone prunes the record, revoking the feed
/// grant it managed: for a held site, the decision waits for the hold's
/// end after the fetch.
#[test]
fn a_check_that_prunes_a_held_site_waits_after_its_fetch() {
    let grants = r#"{"bzz://5a":{"origin":"bzz://5a","connectedAt":1,"lastUsed":1,"autoApprove":{"publish":false,"feeds":false,"signing":false,"messaging":false}}}"#;
    let feeds_text = HELD_FEEDS.replace(
        "\"a\":{\"activeIdentityId\"",
        "\"bzz://5a\":{\"activeIdentityId\"",
    );
    let manifests_text = MANAGED.replace("\"a\":{", "\"bzz://5a\":{");
    let mut world = feeds_world(&feeds_text, grants, Some(&manifests_text));
    world.keeper.hold(HoldId(1), key("bzz://5a"));
    let mut op = world.op(
        ops::MANIFEST,
        &params(
            "check",
            &[("key", s("bzz://5a")), ("url", s("bzz://5a/index.html"))],
        ),
        Caller::Shell,
    );
    let Step::Asks(asks) = op.start(&mut world.stores(T0)) else {
        panic!("a fetch");
    };
    assert_eq!(
        asks[0].need,
        Need::Manifest {
            url: "bzz://5a/freedom-manifest.json".to_owned()
        }
    );
    let before = world.disk.dir.clone();
    let fetched = Event::Manifest(Fetch::Answered {
        status: 404,
        body: Vec::new(),
    });
    assert_eq!(
        op.answer(asks[0].id, fetched, &mut world.stores(T0)),
        Step::Wait(Waiting::Hold)
    );
    assert_eq!(world.disk.dir, before);
    let disk = &mut world.disk;
    world
        .keeper
        .release(HoldId(1), T0, &mut |t: &str| disk.write_feeds(t));
    let Step::Done(outcome) = op.retry(&mut world.stores(T0)) else {
        panic!("done");
    };
    assert_eq!(
        outcome_answer(outcome).unwrap().stringify(),
        r#"{"kind":"legacy","pruned":true,"reason":"absent"}"#
    );
    assert!(!world.keeper.store().has_feed_grant(&key("bzz://5a")));
    assert!(!world.grants.connected(&key("bzz://5a")));
}

/// A user's change of the active identity, or of the feed grant, lets go of
/// what a manifest manages (`detachManagedLater`); the manifest's own
/// projections don't.
#[test]
fn a_users_change_detaches_what_a_manifest_managed() {
    let keys = vault_keys();
    let vault = Vault {
        keys: &keys,
        unlocked: true,
    };
    let managed = r#"{"version":1,"records":{"a":{"managed":{"connection":["feeds"],"identity":["feeds"],"feedGrant":["feeds"]},"acknowledged":{"feeds":{"decision":"managed","source":"sheet","decidedAt":1}},"revision":3}}}"#;
    let mut world = feeds_world(HELD_FEEDS, "{}", Some(managed));
    let record = |world: &mut World| {
        outcome_answer(world.play(
            ops::MANIFEST,
            &params("get", &[("origin", s("a"))]),
            Caller::Shell,
            vault,
            no_fetch,
        ))
        .unwrap()
    };
    // Re-activating the active identity changes nothing to detach.
    world.play(
        ops::IDENTITIES,
        &params(
            "activateIdentity",
            &[("key", s("a")), ("identity_id", s("app-scoped:0"))],
        ),
        Caller::Shell,
        vault,
        no_fetch,
    );
    assert_eq!(
        record(&mut world).get("revision"),
        Some(&JsValue::Number(3.0))
    );
    world.play(
        ops::IDENTITIES,
        &params(
            "activate-feed-identity",
            &[("origin", s("a")), ("identity_id", s("bee-wallet"))],
        ),
        Caller::Chrome,
        vault,
        no_fetch,
    );
    let after = record(&mut world);
    assert_eq!(
        after.stringify(),
        r#"{"managed":{"connection":["feeds"],"feedGrant":["feeds"]},"acknowledged":{"feeds":{"decision":"managed","source":"sheet","decidedAt":1}},"revision":4,"detached":{"identity":true}}"#
    );
    world.play(
        ops::IDENTITIES,
        &params("revoke-feed-access", &[("origin", s("a"))]),
        Caller::Chrome,
        vault,
        no_fetch,
    );
    let after = record(&mut world);
    assert_eq!(after.get("revision"), Some(&JsValue::Number(5.0)));
    assert_eq!(
        after.get("detached").map(JsValue::stringify).as_deref(),
        Some(r#"{"identity":true,"feedGrant":true}"#)
    );
    assert_eq!(
        after.get("managed").map(JsValue::stringify).as_deref(),
        Some(r#"{"connection":["feeds"]}"#)
    );
}

/// Owners (identity-manager.js's): every owner a list needs is asked at
/// once; the answer is read when the last arrives, in the reference's
/// order, and an owner a change made meanwhile needs is asked then.
#[test]
fn owners_are_asked_together_and_read_at_the_last_answer() {
    let keys = vault_keys();
    let vault = Vault {
        keys: &keys,
        unlocked: true,
    };
    let text = HELD_FEEDS.replace(
        r#""bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee","createdAt":3,"lastUsedAt":null}},"feedGranted":true,"grantedAt":1,"feeds":{}},"b""#,
        r#""bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee","createdAt":3,"lastUsedAt":null},"ethereum-wallet:0":{"id":"ethereum-wallet:0","mode":"ethereum-wallet","publisherKeyIndex":null,"walletIndex":0,"label":"Old","createdAt":4,"lastUsedAt":null}},"feedGranted":true,"grantedAt":1,"feeds":{}},"b""#,
    );
    let mut world = feeds_world(&text, "{}", None);
    let call = params("get-origin-identities", &[("origin", s("a"))]);
    let mut op = world.op(ops::IDENTITIES, &call, Caller::Chrome);
    let Step::Asks(asks) = op.start(&mut world.stores(T0)) else {
        panic!("asks");
    };
    let needs: Vec<&Need> = asks.iter().map(|a| &a.need).collect();
    assert_eq!(
        needs,
        [
            &Need::Owner(SignKey::Publisher(0)),
            &Need::Owner(SignKey::Publisher(1)),
            &Need::Owner(SignKey::BeeWallet),
            &Need::Accounts,
        ]
    );
    // Meanwhile another identity is made: its owner is asked once the
    // others are in.
    world
        .feed_change(FeedChange::CreateAppScopedIdentity {
            key: key("a"),
            options: js(r#"{"activate":false}"#),
            source: Source::User,
        })
        .unwrap();
    let mut step = Step::Ended;
    for ask in asks.iter().rev() {
        step = op.answer(ask.id, vault.event(&ask.need), &mut world.stores(T0));
    }
    let Step::Asks(more) = step else {
        panic!("one more: {step:?}");
    };
    assert_eq!(more.len(), 1);
    assert_eq!(more[0].need, Need::Owner(SignKey::Publisher(2)));
    let Step::Done(outcome) = op.answer(
        more[0].id,
        vault.event(&more[0].need),
        &mut world.stores(T0),
    ) else {
        panic!("done");
    };
    let mut owners = vault;
    let read = world
        .keeper
        .store()
        .origin_identity_state_with_owners(&key("a"), &mut owners)
        .unwrap();
    assert_eq!(
        outcome_answer(outcome).unwrap().stringify(),
        read.stringify()
    );
    // A locked vault: the first owner in order gives its mode's text.
    let locked = Vault {
        keys: &keys,
        unlocked: false,
    };
    let got = world.play(ops::IDENTITIES, &call, Caller::Chrome, locked, no_fetch);
    assert_eq!(
        outcome_answer(got).unwrap_err().message,
        "Vault must be unlocked to derive publisher keys"
    );
    // The vault's own failure is its text.
    let mut op = world.op(ops::IDENTITIES, &call, Caller::Chrome);
    let Step::Asks(asks) = op.start(&mut world.stores(T0)) else {
        panic!("asks");
    };
    let mut step = Step::Ended;
    for ask in &asks {
        let event = match ask.need {
            Need::Owner(SignKey::Publisher(1)) => Event::Owner(Err(key("vault busy"))),
            ref need => vault.event(need),
        };
        step = op.answer(ask.id, event, &mut world.stores(T0));
    }
    let Step::Done(outcome) = step else {
        panic!("done");
    };
    assert_eq!(outcome_answer(outcome).unwrap_err().message, "vault busy");
    // The preview asks the next index's owner.
    let mut op = world.op(
        ops::IDENTITIES,
        &params("previewAppScopedIdentity", &[("key", s("b"))]),
        Caller::Shell,
    );
    let Step::Asks(asks) = op.start(&mut world.stores(T0)) else {
        panic!("asks");
    };
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].need, Need::Owner(SignKey::Publisher(3)));
}

/// `getEthereumWalletIdentityReferences` through main's op: the active ones
/// first, then by site in ICU's order (`a` before `A`), a site outside
/// printable ASCII by code unit (deviation `collation`); feed names by
/// code unit.
#[test]
fn references_in_icus_order() {
    let keys = vault_keys();
    let vault = Vault {
        keys: &keys,
        unlocked: true,
    };
    let site = |active: bool, feeds: &str| {
        format!(
            r#"{{"activeIdentityId":"{}","identities":{{"bee-wallet":{{"id":"bee-wallet","mode":"bee-wallet"}},"ethereum-wallet:0":{{"id":"ethereum-wallet:0","mode":"ethereum-wallet","walletIndex":0}},"ethereum-wallet:1":{{"id":"ethereum-wallet:1","mode":"ethereum-wallet","walletIndex":1}}}},"feedGranted":false,"grantedAt":1,"feeds":{feeds}}}"#,
            if active {
                "ethereum-wallet:0"
            } else {
                "bee-wallet"
            }
        )
    };
    let named = r#"{"b":{"identityId":"ethereum-wallet:0"},"B":{"identityId":"ethereum-wallet:0"},"a":{"identityId":"ethereum-wallet:0"},"x":{"identityId":"bee-wallet"}}"#;
    let text = format!(
        r#"{{"version":2,"nextPublisherKeyIndex":0,"origins":{{"https://b.example":{},"https://A.example":{},"https://a.example":{},"ens:é.eth":{},"ens:z.eth":{},"https://c.example":{},"https://active.example":{}}}}}"#,
        site(false, named),
        site(false, named),
        site(false, r#"{"n":{"identityId":"ethereum-wallet:0"}}"#),
        site(false, named),
        site(false, named),
        site(false, "{}"),
        site(true, "{}"),
    );
    let mut world = feeds_world(&text, "{}", None);
    let call = |index: JsValue| {
        params(
            "getEthereumWalletIdentityReferences",
            &[("wallet_index", index)],
        )
    };
    let got = outcome_answer(world.play(
        ops::IDENTITIES,
        &call(JsValue::Number(0.0)),
        Caller::Shell,
        vault,
        no_fetch,
    ))
    .unwrap();
    let order: Vec<&str> = got
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.get("origin").and_then(JsValue::as_str).unwrap())
        .collect();
    // https://c.example has the identity but neither uses it nor is
    // active: left out.
    assert_eq!(
        order,
        [
            "https://active.example",
            "ens:z.eth",
            "ens:\u{e9}.eth",
            "https://a.example",
            "https://A.example",
            "https://b.example"
        ]
    );
    assert_eq!(
        got.as_array().unwrap()[1].stringify(),
        r#"{"origin":"ens:z.eth","identityId":"ethereum-wallet:0","active":false,"feedNames":["B","a","b"],"feedCount":3}"#
    );
    // Wallet 1: no site uses it.
    let none = world.play(
        ops::IDENTITIES,
        &call(JsValue::Number(1.0)),
        Caller::Shell,
        vault,
        no_fetch,
    );
    assert_eq!(none, Outcome::Result(Value::Array(Vec::new())));
    for bad in [
        JsValue::Number(-1.0),
        JsValue::Number(1.5),
        s("0"),
        JsValue::Undefined,
    ] {
        let got = world.play(ops::IDENTITIES, &call(bad), Caller::Shell, vault, no_fetch);
        assert_eq!(
            outcome_answer(got).unwrap_err().message,
            "Wallet index must be a non-negative integer"
        );
    }
    // Main's own: the chrome is refused.
    assert_eq!(
        Call::parse(ops::IDENTITIES, &call(JsValue::Number(0.0)), Caller::Chrome).unwrap_err(),
        Refused::Forbidden("getEthereumWalletIdentityReferences")
    );
}

/// Each op's wire form, refused when a member is missing, unknown or of
/// another shape; main's ops refused to the chrome.
#[test]
fn wrong_shape_calls_are_refused() {
    let typed_string = || to_typed(&s("k"));
    let cases: [(&str, &str, &[&str], &[&str]); 27] = [
        (ops::IDENTITIES, "get-all-origins", &[], &[]),
        (ops::IDENTITIES, "has-feed-identity", &["origin"], &[]),
        (ops::IDENTITIES, "get-identity-mode", &["origin"], &[]),
        (ops::IDENTITIES, "get-origin-identities", &["origin"], &[]),
        (
            ops::IDENTITIES,
            "create-app-scoped-identity",
            &["origin"],
            &["options"],
        ),
        (
            ops::IDENTITIES,
            "ensure-ant-wallet-identity",
            &["origin"],
            &["options"],
        ),
        (
            ops::IDENTITIES,
            "activate-feed-identity",
            &["origin"],
            &["identity_id"],
        ),
        (ops::IDENTITIES, "set-feed-identity", &[], &[]),
        (ops::IDENTITIES, "revoke-feed-access", &["origin"], &[]),
        (
            ops::IDENTITIES,
            "getOriginIdentityStateWithOwners",
            &["key"],
            &[],
        ),
        (
            ops::IDENTITIES,
            "previewAppScopedIdentity",
            &["key"],
            &["options"],
        ),
        (
            ops::IDENTITIES,
            "createAppScopedIdentityAt",
            &["key"],
            &["index", "options"],
        ),
        (
            ops::IDENTITIES,
            "ensureAntWalletIdentity",
            &["key"],
            &["options"],
        ),
        (
            ops::IDENTITIES,
            "activateIdentity",
            &["key"],
            &["identity_id"],
        ),
        (ops::IDENTITIES, "grantFeedAccess", &["key"], &[]),
        (ops::IDENTITIES, "hasFeedGrant", &["key"], &[]),
        (ops::IDENTITIES, "assertFeedGrantable", &["key"], &[]),
        (
            ops::IDENTITIES,
            "getEthereumWalletIdentityReferences",
            &[],
            &["wallet_index"],
        ),
        (ops::HISTORY, "list", &[], &[]),
        (ops::HISTORY, "clear", &[], &[]),
        (ops::HISTORY, "remove", &[], &["id"]),
        (ops::MANIFEST, "check", &["key", "url"], &["eager"]),
        (
            ops::MANIFEST,
            "decide",
            &["key", "token", "outcome"],
            &["live"],
        ),
        (ops::MANIFEST, "release", &["token"], &[]),
        (ops::MANIFEST, "get", &["origin"], &[]),
        (
            ops::MANIFEST,
            "use-individual",
            &["origin"],
            &["capability"],
        ),
        (ops::MANIFEST, "disconnect", &["origin"], &[]),
    ];
    for (method, op, required, optional) in cases {
        let build = |members: &[&str]| {
            let mut out = JsValue::Object(Vec::new());
            out.set("op", s(op));
            for name in members {
                out.set(
                    *name,
                    if *name == "live" || *name == "eager" {
                        to_typed(&JsValue::Bool(true))
                    } else {
                        typed_string()
                    },
                );
            }
            out
        };
        let mut all: Vec<&str> = required.to_vec();
        all.extend(optional);
        // `decide`'s live is required too.
        let all_required: Vec<&str> = if op == "decide" {
            all.clone()
        } else {
            required.to_vec()
        };
        let shell = |p: &JsValue| Call::parse(method, p, Caller::Shell);
        assert!(shell(&build(&all)).is_ok(), "{op}: every member");
        assert!(
            shell(&build(&all_required)).is_ok(),
            "{op}: the required ones"
        );
        for missing in &all_required {
            let fewer: Vec<&str> = all_required
                .iter()
                .copied()
                .filter(|n| n != missing)
                .collect();
            assert!(
                matches!(shell(&build(&fewer)), Err(Refused::Invalid(_))),
                "{op} without {missing}"
            );
        }
        let mut extra = build(&all);
        extra.set("nope", to_typed(&JsValue::Null));
        assert!(
            matches!(shell(&extra), Err(Refused::Invalid(_))),
            "{op} with nope"
        );
        // A site key, token, URL or outcome that isn't a string.
        for name in &all_required {
            let mut wrong = build(&all);
            wrong.set(*name, to_typed(&JsValue::Number(1.0)));
            assert!(
                matches!(shell(&wrong), Err(Refused::Invalid(_))),
                "{op}: {name} a number"
            );
        }
        // An untyped member.
        if let Some(name) = all.first() {
            let mut raw = build(&all);
            raw.set(*name, s("k"));
            assert!(
                matches!(shell(&raw), Err(Refused::Invalid(_))),
                "{op}: {name} untyped"
            );
        }
        let chrome = Call::parse(method, &build(&all), Caller::Chrome);
        if op.chars().next().is_some_and(char::is_lowercase) && op.chars().any(char::is_uppercase) {
            assert_eq!(
                chrome,
                Err(Refused::Forbidden(op_name(op))),
                "{op} from the chrome"
            );
        } else if method != ops::MANIFEST {
            assert!(chrome.is_ok(), "{op} from the chrome");
        }
    }
}

/// Main's op names, as `Refused::Forbidden` carries them.
fn op_name(op: &str) -> &'static str {
    [
        "getOriginIdentityStateWithOwners",
        "previewAppScopedIdentity",
        "createAppScopedIdentityAt",
        "ensureAntWalletIdentity",
        "activateIdentity",
        "grantFeedAccess",
        "hasFeedGrant",
        "assertFeedGrantable",
        "getEthereumWalletIdentityReferences",
    ]
    .into_iter()
    .find(|name| *name == op)
    .unwrap()
}

/// The chrome's refused feed grant, the store's reads, a history id that
/// can't be bound, a failed write: each answered as the reference or the
/// core's write answers it.
#[test]
fn the_other_answers() {
    let keys = vault_keys();
    let vault = Vault {
        keys: &keys,
        unlocked: true,
    };
    let mut world = feeds_world(HELD_FEEDS, "{}", None);
    let play = |world: &mut World, method: &str, op: &str, members: &[(&str, JsValue)], caller| {
        outcome_answer(world.play(method, &params(op, members), caller, vault, no_fetch))
    };
    let refused = play(
        &mut world,
        ops::IDENTITIES,
        "set-feed-identity",
        &[],
        Caller::Chrome,
    );
    assert_eq!(
        refused.unwrap_err().message,
        ops::identities::FEED_GRANT_REFUSED
    );
    let id = |world: &mut World, op: &str, site: &str| {
        play(
            world,
            ops::IDENTITIES,
            op,
            &[("origin", s(site))],
            Caller::Chrome,
        )
    };
    assert_eq!(
        id(&mut world, "has-feed-identity", "a"),
        Ok(JsValue::Bool(true))
    );
    assert_eq!(
        id(&mut world, "has-feed-identity", "z"),
        Ok(JsValue::Bool(false))
    );
    assert_eq!(
        id(&mut world, "get-identity-mode", "b"),
        Ok(s("bee-wallet"))
    );
    assert_eq!(id(&mut world, "get-identity-mode", "z"), Ok(JsValue::Null));
    let main = |world: &mut World, op: &str, site: &str| {
        play(
            world,
            ops::IDENTITIES,
            op,
            &[("key", s(site))],
            Caller::Shell,
        )
    };
    assert_eq!(
        main(&mut world, "hasFeedGrant", "a"),
        Ok(JsValue::Bool(true))
    );
    assert_eq!(
        main(&mut world, "assertFeedGrantable", "a"),
        Ok(JsValue::Undefined)
    );
    // The chrome's handlers spread their options and force `source`.
    let state = play(
        &mut world,
        ops::IDENTITIES,
        "create-app-scoped-identity",
        &[("origin", s("c")), ("options", s("xy"))],
        Caller::Chrome,
    )
    .unwrap();
    assert_eq!(state.get("activeIdentityId"), Some(&s("app-scoped:2")));
    // createAppScopedIdentityAt on a taken index.
    let taken = main_with(
        &mut world,
        vault,
        "createAppScopedIdentityAt",
        &[("key", s("c")), ("index", JsValue::Number(0.0))],
    );
    let taken = taken.unwrap_err();
    assert_eq!(taken.code, Some("identity_taken"));
    // A failed write: the write's text, the store as it was.
    world.disk.fail = Some(feeds::FILE_NAME);
    let before = world.keeper.store().clone();
    let failed = id(&mut world, "revoke-feed-access", "a").unwrap_err();
    assert_eq!(failed.message, "ENOSPC: no space left on device, write");
    assert_eq!(*world.keeper.store(), before);
    world.disk.fail = None;
    // History: an id better-sqlite3 can't bind.
    let dir = TempDir::new("ops-remove");
    world.disk.db = Some(open_history(&dir.0, T0));
    let bad = play(
        &mut world,
        ops::HISTORY,
        "remove",
        &[("id", JsValue::Bool(true))],
        Caller::Chrome,
    );
    assert_eq!(
        bad.unwrap_err(),
        Thrown {
            name: fc_swarm_provider::stores::ErrorName::TypeError,
            message: "SQLite3 can only bind numbers, strings, bigints, buffers, and null"
                .to_owned(),
            code: None,
        }
    );
    assert_eq!(
        play(
            &mut world,
            ops::HISTORY,
            "remove",
            &[("id", JsValue::Number(1.0))],
            Caller::Chrome
        ),
        Ok(JsValue::Bool(false))
    );
    // A manifest save that fails: its text, and the store read again from
    // the file at the next op.
    world
        .disk
        .dir
        .insert(manifests::FILE_NAME.to_owned(), MANAGED.to_owned());
    world.disk.fail = Some(manifests::FILE_NAME);
    let failed = play(
        &mut world,
        ops::MANIFEST,
        "disconnect",
        &[("origin", s("a"))],
        Caller::Shell,
    );
    assert_eq!(
        failed.unwrap_err().message,
        "ENOSPC: no space left on device, write"
    );
    assert!(!world.manifests.is_loaded());
    world.disk.fail = None;
    let record = play(
        &mut world,
        ops::MANIFEST,
        "get",
        &[("origin", s("a"))],
        Caller::Shell,
    )
    .unwrap();
    assert_eq!(record.get("revision"), Some(&JsValue::Number(1.0)));
    // A page consent: one `release` spends it, and a decision on a token
    // that isn't the key's, or with `live: false`, writes nothing.
    let expired = play(
        &mut world,
        ops::MANIFEST,
        "decide",
        &[
            ("key", s("a")),
            ("token", s("t")),
            ("outcome", s("allow")),
            ("live", JsValue::Bool(true)),
        ],
        Caller::Shell,
    );
    assert_eq!(expired.unwrap_err().message, "Manifest consent expired");
    assert_eq!(
        play(
            &mut world,
            ops::MANIFEST,
            "release",
            &[("token", s("t"))],
            Caller::Shell
        ),
        Ok(JsValue::Undefined)
    );
}

fn main_with(
    world: &mut World,
    vault: Vault<'_>,
    op: &str,
    members: &[(&str, JsValue)],
) -> Result<JsValue, Thrown> {
    outcome_answer(world.play(
        ops::IDENTITIES,
        &params(op, members),
        Caller::Shell,
        vault,
        no_fetch,
    ))
}

/// A decision main read as not live spends the consent: `{ refused: true }`,
/// nothing written, and the token gone.
#[test]
fn a_decision_that_isnt_live_is_refused() {
    let cases = stores_section();
    let keys = vault_keys();
    let vault = Vault {
        keys: &keys,
        unlocked: true,
    };
    let case = cases
        .iter()
        .find(|c| c.get("id").and_then(JsValue::as_str) == Some("manifest-allow-publish"))
        .unwrap();
    let site = field(case, "site").clone();
    let step = &field(case, "steps").as_array().unwrap()[0];
    let manifest = str_of(field(step, "manifest")).as_bytes().to_vec();
    let mut world = World::new(
        FeedStore::empty(),
        field(case, "grants").clone(),
        Dir::new(),
    );
    let check = params(
        "check",
        &[
            ("key", site.clone()),
            (
                "url",
                JsValue::string(format!("{}/index.html", str_of(&site))),
            ),
            ("eager", JsValue::Bool(true)),
        ],
    );
    let answer = outcome_answer(
        world.play(ops::MANIFEST, &check, Caller::Shell, vault, |_| {
            Fetch::Answered {
                status: 200,
                body: manifest.clone(),
            }
        }),
    )
    .unwrap();
    let token = answer.get("token").unwrap().clone();
    let before = world.disk.dir.clone();
    let decide = |live: bool| {
        params(
            "decide",
            &[
                ("key", site.clone()),
                ("token", token.clone()),
                ("outcome", s("allow")),
                ("live", JsValue::Bool(live)),
            ],
        )
    };
    let refused = world.play(
        ops::MANIFEST,
        &decide(false),
        Caller::Shell,
        vault,
        no_fetch,
    );
    assert_eq!(
        outcome_answer(refused).unwrap().stringify(),
        r#"{"refused":true}"#
    );
    assert_eq!(world.disk.dir, before);
    let spent = world.play(ops::MANIFEST, &decide(true), Caller::Shell, vault, no_fetch);
    assert_eq!(
        outcome_answer(spent).unwrap_err().message,
        "Manifest consent expired"
    );
    // Another key's token is expired for this one.
    let answer = outcome_answer(
        world.play(ops::MANIFEST, &check, Caller::Shell, vault, |_| {
            Fetch::Answered {
                status: 200,
                body: manifest.clone(),
            }
        }),
    )
    .unwrap();
    let other = params(
        "decide",
        &[
            ("key", s("bzz://other")),
            ("token", answer.get("token").unwrap().clone()),
            ("outcome", s("allow")),
            ("live", JsValue::Bool(true)),
        ],
    );
    let got = world.play(ops::MANIFEST, &other, Caller::Shell, vault, no_fetch);
    assert_eq!(
        outcome_answer(got).unwrap_err().message,
        "Manifest consent expired"
    );
    // A failed fetch is unresolved, with its backoff.
    let mut fresh = World::new(FeedStore::empty(), JsValue::Object(Vec::new()), Dir::new());
    let got = fresh.play(ops::MANIFEST, &check, Caller::Shell, vault, |_| {
        Fetch::Failed
    });
    let got = outcome_answer(got).unwrap();
    assert_eq!(got.get("kind"), Some(&s("legacy")));
    assert_eq!(got.get("reason"), Some(&s("unresolved")));
}
