//! `vectors/profiles.json` replayed (design 0013, PRF-3): every pure
//! function's answers, proper-lockfile's staleness decision, and each
//! scenario's steps over an in-memory store at `/vectors`, with each step's
//! result and every file's text after it, byte for byte.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use fc_json::JsValue;
use fc_profile::{Error, OpenArgs, OpenOutcome, Options, Store, StoreError, Style, lock};
use serde::Deserialize;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../vectors/profiles.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    meta: Value,
    root: String,
    sanitize: Vec<Value>,
    display_names: Vec<DisplayName>,
    hashes: Vec<Hash>,
    dev_port_offsets: Vec<Offset>,
    ports: Vec<PortCase>,
    allocate_slot: Vec<SlotCase>,
    node_configs: Vec<NodeCase>,
    lock_staleness: Vec<LockCase>,
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
struct DisplayName {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Hash {
    path: String,
    hash: String,
    checkout_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Offset {
    checkout_hash: String,
    offset: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortCase {
    slot: f64,
    dev: bool,
    checkout_hash: Option<String>,
    ports: Ports,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ports {
    bee_api: f64,
    bee_p2p: f64,
    tor_socks: f64,
}

#[derive(Deserialize)]
struct SlotCase {
    profiles: String,
    id: String,
    slot: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeCase {
    id: String,
    nodes: String,
    slot: f64,
    dev: bool,
    checkout_hash: Option<String>,
    rebased: String,
    filled: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockCase {
    lock: String,
    stale_ms: u64,
    age_ms: i64,
    locked: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Scenario {
    id: String,
    dev: bool,
    checkout_hash: Option<String>,
    files: BTreeMap<String, String>,
    dirs: Vec<String>,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Step {
    op: String,
    #[serde(default)]
    args: Option<StepArgs>,
    #[serde(default)]
    running: Vec<String>,
    now: Option<String>,
    id: Option<String>,
    display_name: Option<String>,
    active: Option<String>,
    exclude: Option<String>,
    user_data_dir: Option<String>,
    protocol: Option<String>,
    metadata: Option<String>,
    updates: Option<String>,
    confirm: Option<String>,
    /// 0013's Deviations row where the core answers otherwise, with its
    /// answer (`core`) beside the reference's (`result`).
    deviation: Option<String>,
    core: Option<Value>,
    result: Value,
    files: BTreeMap<String, String>,
    dirs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StepArgs {
    profile: Option<String>,
    switch: Option<String>,
    env_profile: Option<String>,
    #[serde(default)]
    runtime: bool,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS).unwrap()
}

/// A JSON value from the vectors, as JavaScript holds it.
fn js(value: &Value) -> JsValue {
    fc_json::parse(&serde_json::to_string(value).unwrap()).unwrap()
}

#[test]
fn meta_names_the_reference() {
    let v = vectors();
    assert_eq!(
        v.meta["freedomBrowserCommit"],
        "7f85551d82bddb1337df73b331785e969d62d1b9"
    );
    assert_eq!(v.meta["packages"]["proper-lockfile"], "4.1.2");
    assert_eq!(v.root, "/vectors");
}

#[test]
fn ids_names_hashes_and_ports() {
    let v = vectors();
    for case in &v.sanitize {
        let input = case["input"].as_str().unwrap();
        match fc_profile::sanitize_profile_id(input) {
            Ok(id) => assert_eq!(Some(id.as_str()), case["id"].as_str(), "{input:?}"),
            Err(Error::Refused(message)) => {
                assert_eq!(case["error"], "refused", "{input:?}");
                assert_eq!(
                    Some(message.as_str()),
                    case["message"].as_str(),
                    "{input:?}"
                );
            }
            Err(other) => panic!("{input:?}: {other:?}"),
        }
    }
    for case in &v.display_names {
        assert_eq!(fc_profile::display_name_from_id(&case.id), case.name);
    }
    for case in &v.hashes {
        assert_eq!(fc_profile::hash_path(&case.path), case.hash);
        assert_eq!(fc_profile::checkout_id(&case.path), case.checkout_id);
    }
    for case in &v.dev_port_offsets {
        assert_eq!(
            fc_profile::dev_port_offset(&case.checkout_hash),
            case.offset
        );
    }
    for case in &v.ports {
        let ports = fc_profile::managed_ports(case.slot, case.dev, case.checkout_hash.as_deref());
        assert_eq!(
            (ports.bee_api, ports.bee_p2p, ports.tor_socks),
            (case.ports.bee_api, case.ports.bee_p2p, case.ports.tor_socks),
            "slot {} dev {} {:?}",
            case.slot,
            case.dev,
            case.checkout_hash
        );
    }
    for case in &v.allocate_slot {
        let profiles = fc_json::parse(&case.profiles).unwrap();
        assert_eq!(
            fc_profile::allocate_slot(profiles.as_array().unwrap(), &case.id),
            case.slot,
            "{} {}",
            case.profiles,
            case.id
        );
    }
}

#[test]
fn node_configurations() {
    for case in vectors().node_configs {
        let nodes = fc_json::parse(&case.nodes).unwrap();
        let ports = fc_profile::managed_ports(case.slot, case.dev, case.checkout_hash.as_deref());
        assert_eq!(
            fc_profile::rebase_node_config(&nodes, &ports).stringify(),
            case.rebased,
            "{} rebased",
            case.id
        );
        assert_eq!(
            fc_profile::fill_missing_node_config(&nodes, &ports).stringify(),
            case.filled,
            "{} filled",
            case.id
        );
    }
}

#[test]
fn lock_staleness() {
    let now = 1_800_000_000_000;
    for case in vectors().lock_staleness {
        assert_eq!(
            !lock::is_stale(now - case.age_ms, now, case.stale_ms),
            case.locked,
            "{} at {} ms",
            case.lock,
            case.age_ms
        );
    }
}

/// The scenarios' filesystem: files and directories under `/vectors`.
struct Memory {
    root: String,
    files: BTreeMap<String, String>,
    dirs: BTreeSet<String>,
}

impl Memory {
    fn new(root: &str, files: &BTreeMap<String, String>, dirs: &[String]) -> Memory {
        let mut memory = Memory {
            root: root.to_owned(),
            files: BTreeMap::new(),
            dirs: BTreeSet::new(),
        };
        for dir in dirs {
            memory.make_dirs(&format!("{root}/{dir}"));
        }
        for (name, text) in files {
            let path = format!("{root}/{name}");
            memory.make_dirs(&Style::Posix.dirname(&path));
            memory.files.insert(path, text.clone());
        }
        memory
    }

    fn make_dirs(&mut self, path: &str) {
        let mut current = path.to_owned();
        while current.starts_with(&format!("{}/", self.root)) {
            self.dirs.insert(current.clone());
            current = Style::Posix.dirname(&current);
        }
    }

    fn relative(&self, path: &str) -> String {
        path.strip_prefix(&format!("{}/", self.root))
            .unwrap()
            .to_owned()
    }
}

impl Store for Memory {
    fn read(&mut self, path: &str) -> Result<Option<String>, StoreError> {
        if self.dirs.contains(path) {
            return Err(StoreError {
                path: path.into(),
                message: "a directory".into(),
            });
        }
        Ok(self.files.get(path).cloned())
    }

    fn is_dir(&mut self, path: &str) -> Result<bool, StoreError> {
        Ok(self.dirs.contains(path))
    }

    fn list_dirs(&mut self, path: &str) -> Result<Vec<String>, StoreError> {
        let prefix = format!("{path}/");
        Ok(self
            .dirs
            .iter()
            .filter_map(|dir| dir.strip_prefix(&prefix))
            .filter(|rest| !rest.contains('/'))
            .map(str::to_owned)
            .collect())
    }

    fn ensure_dir(&mut self, path: &str) -> Result<(), StoreError> {
        self.make_dirs(path);
        Ok(())
    }

    fn write(&mut self, path: &str, text: &str) -> Result<(), StoreError> {
        self.make_dirs(&Style::Posix.dirname(path));
        self.files.insert(path.to_owned(), text.to_owned());
        Ok(())
    }

    fn resolve(&self, path: &str) -> String {
        Style::Posix.normalize(path)
    }
}

/// An operation's refusal, as the vectors classify the reference's.
fn classified(error: &Error) -> Value {
    match error {
        Error::Refused(message) => serde_json::json!({ "error": "refused", "message": message }),
        Error::Unsupported { .. } => {
            serde_json::json!({ "error": "unsupported", "message": error.message() })
        }
        Error::Unreadable { .. } => serde_json::json!({ "error": "unreadable" }),
        Error::Malformed { .. } => serde_json::json!({ "error": "malformed" }),
        Error::Store(e) => panic!("store: {e:?}"),
    }
}

fn text(result: Result<JsValue, Error>) -> Value {
    match result {
        Ok(value) => serde_json::json!({ "value": value.stringify() }),
        Err(error) => classified(&error),
    }
}

fn run(memory: &mut Memory, scenario: &Scenario, step: &Step) -> Value {
    let app_root = format!("{}/app", memory.root);
    let opts = Options {
        dev: scenario.dev,
        checkout_hash: scenario.checkout_hash.clone(),
        default_profile_dir: None,
        style: Style::Posix,
    };
    let now = step.now.clone().unwrap_or_default();
    match step.op.as_str() {
        "open" => {
            let args = step.args.as_ref().unwrap();
            let args = OpenArgs {
                profile: args.profile.clone(),
                switch: args.switch.clone(),
                env_profile: args.env_profile.clone(),
                runtime: args.runtime,
            };
            let running = step.running.clone();
            let mut is_open = |id: &str, _dir: &str| running.iter().any(|r| r == id);
            match fc_profile::open(memory, &app_root, &opts, &args, &now, &mut is_open) {
                Ok(OpenOutcome::Opened(opened)) => serde_json::json!({
                    "value": {
                        "outcome": "opened",
                        "switchOnly": opened.switch_only,
                        "id": serde_json::from_str::<Value>(&opened.id.stringify()).unwrap(),
                        "displayName": serde_json::from_str::<Value>(&opened.display_name.stringify()).unwrap(),
                        "userDataDir": opened.user_data_dir,
                        "catalogPath": opened.catalog_path,
                        "metadata": opened.metadata.stringify(),
                    }
                }),
                Ok(OpenOutcome::SwitchRefused(message)) => {
                    serde_json::json!({ "outcome": "switch_refused", "message": message })
                }
                Err(error) => classified(&error),
            }
        }
        "create" => text(fc_profile::create(
            memory,
            &app_root,
            &opts,
            step.display_name.as_deref().unwrap(),
            step.id.as_deref(),
            &now,
        )),
        "rename" => text(fc_profile::rename(
            memory,
            &app_root,
            Style::Posix,
            step.id.as_deref().unwrap(),
            step.display_name.as_deref().unwrap(),
        )),
        "import" => text(fc_profile::import(
            memory,
            &app_root,
            &opts,
            step.id.as_deref().unwrap(),
            &now,
        )),
        "update-nodes" => text(fc_profile::update_nodes(
            memory,
            &app_root,
            Style::Posix,
            step.id.as_deref().unwrap(),
            step.user_data_dir.as_deref().unwrap(),
            &fc_json::parse(step.metadata.as_deref().unwrap()).unwrap(),
            step.protocol.as_deref().unwrap(),
            &fc_json::parse(step.updates.as_deref().unwrap()).unwrap(),
        )),
        "reserved-ports" => text(
            fc_profile::reserved_ports(memory, &app_root, &opts, step.exclude.as_deref())
                .map(|ports| JsValue::Array(ports.into_iter().map(JsValue::Number).collect())),
        ),
        "list" => text(fc_profile::list(
            memory,
            &app_root,
            Style::Posix,
            step.active.as_deref(),
        )),
        "delete-validate" => {
            let id = step.id.as_deref().unwrap();
            let confirm = step.confirm.as_deref().unwrap();
            let validated =
                fc_profile::validate_deletion(memory, &app_root, Style::Posix, id, confirm);
            // The delete itself checks the same, under the catalog's lock.
            let planned = fc_profile::plan_deletion(memory, &app_root, &opts, id, confirm);
            assert_eq!(
                validated.clone().err(),
                planned.err(),
                "{id}: the delete's own checks"
            );
            match validated {
                Ok(()) => serde_json::json!({ "value": "valid" }),
                Err(error) => classified(&error),
            }
        }
        other => panic!("unknown step {other}"),
    }
}

#[test]
fn scenarios() {
    let v = vectors();
    for scenario in &v.scenarios {
        let mut memory = Memory::new(&v.root, &scenario.files, &scenario.dirs);
        for (n, step) in scenario.steps.iter().enumerate() {
            let at = format!("{} step {n} ({})", scenario.id, step.op);
            let result = run(&mut memory, scenario, step);
            let expected = match (&step.deviation, &step.core) {
                (None, None) => &step.result,
                (Some(deviation), Some(core)) => {
                    assert_eq!(deviation, "profile-delete-overlap", "{at}: a row of 0013's");
                    core
                }
                _ => panic!("{at}: a deviation names its row and the core's answer"),
            };
            assert_eq!(&result, expected, "{at}: result");
            let files: BTreeMap<String, String> = memory
                .files
                .iter()
                .map(|(path, text)| (memory.relative(path), text.clone()))
                .collect();
            assert_eq!(files, step.files, "{at}: files");
            let mut dirs: Vec<String> = memory.dirs.iter().map(|d| memory.relative(d)).collect();
            let mut expected = step.dirs.clone();
            dirs.sort();
            expected.sort();
            assert_eq!(dirs, expected, "{at}: dirs");
        }
    }
}

/// `js` is used by the scenarios' expected values where a JSON value must be
/// compared as JavaScript holds it.
#[test]
fn values_round_trip() {
    assert_eq!(js(&serde_json::json!({"a": 1})).stringify(), r#"{"a":1}"#);
}
