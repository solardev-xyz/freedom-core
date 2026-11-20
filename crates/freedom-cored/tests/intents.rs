//! The wallet's intent records in the core (design 0013, "The intent
//! journal"; PRF-5e-3): vectors/stores.json's `intents`, which the pinned
//! reference's intent-store.js produced, replayed over the wire, each
//! file byte for byte, with `run` written as main passes it; the reads a
//! fresh load gives, served from main's file before `intents` is in
//! `store_moved`, and every write `not_moved` then; main's alone; members
//! checked before the rules; a failed append, admission compaction and
//! `withdraw_origin` compaction; a damaged file set aside.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use fc_json::JsValue;
use serde_json::{Value, json};

const FILE: &str = "wallet-intents.jsonl";
const WRITE_FAIL: &str = "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL";
const WRITES: [&str; 9] = [
    "intents.commit",
    "intents.handoff",
    "intents.outcome",
    "intents.settle",
    "intents.void",
    "intents.retire",
    "intents.track",
    "intents.withdraw_origin",
    "intents.compact",
];
const READS: [&str; 7] = [
    "intents.get",
    "intents.by_key",
    "intents.held",
    "intents.list",
    "intents.held_nonces",
    "intents.usage",
    "intents.void_refusal",
];
/// The run a fresh load's void refusals are asked for (the vectors').
const LOAD_RUN: &str = "00000000-0000-4000-8000-000000900001";

static UNDEFINED: JsValue = JsValue::Undefined;

fn intents() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/stores.json");
    let all = fc_json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    all.get("intents").unwrap().clone()
}

fn field<'a>(value: &'a JsValue, key: &str) -> &'a JsValue {
    value.get(key).unwrap_or(&UNDEFINED)
}

fn items(value: &JsValue) -> &[JsValue] {
    value.as_array().expect("an array")
}

/// A vector value as the wire's JSON.
fn wire(value: &JsValue) -> Value {
    serde_json::from_str(&value.stringify()).unwrap()
}

/// The journal's bytes for these records.
fn lines(records: &[JsValue]) -> Vec<u8> {
    records
        .iter()
        .flat_map(|r| fc_store::journal::encode_line(r).unwrap())
        .collect()
}

/// A reference argument object as `intents.*`'s members: snake_case, the
/// reference's handoff answer dropped, `run` added.
fn members(call: &JsValue, run: Option<&str>) -> String {
    let mut props: Vec<(fc_json::JsString, JsValue)> = Vec::new();
    if let JsValue::Object(given) = call {
        for (key, value) in given {
            let key = match key.to_string().as_str() {
                "result" => continue,
                "intentId" => "intent_id".to_owned(),
                "chainId" => "chain_id".to_owned(),
                "handoffId" => "handoff_id".to_owned(),
                "reasonClass" => "reason_class".to_owned(),
                "unreadSince" => "unread_since".to_owned(),
                other => other.to_owned(),
            };
            props.push((key.as_str().into(), value.clone()));
        }
    }
    if let Some(run) = run {
        props.push(("run".into(), JsValue::string(run)));
    }
    JsValue::Object(props).stringify()
}

fn code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("")
}

/// A profile, the files the hooks read, and the core running on it.
struct Main {
    _root: tempfile::TempDir,
    data: PathBuf,
    locks: PathBuf,
    grant_root: PathBuf,
    hooks: PathBuf,
    core: Option<common::Core>,
    next_id: u64,
    moved: Vec<&'static str>,
}

impl Main {
    fn new(moved: &[&'static str]) -> Main {
        let (root, data, locks) = common::dirs();
        let grant_root = root.path().join("userData");
        std::fs::create_dir_all(&grant_root).unwrap();
        let hooks = root.path().join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        Main {
            _root: root,
            data,
            locks,
            grant_root,
            hooks,
            core: None,
            next_id: 10,
            moved: moved.to_vec(),
        }
    }

    fn hook(&self, name: &str) -> PathBuf {
        self.hooks.join(name)
    }

    fn set(&self, name: &str, text: &str) {
        std::fs::write(self.hook(name), text).unwrap();
    }

    fn start(&mut self) -> Value {
        self.core = None;
        let env = [
            ("clock", "FREEDOM_CORED_TEST_WALL_CLOCK"),
            ("ids", "FREEDOM_CORED_TEST_INTENT_IDS"),
            ("limits", "FREEDOM_CORED_TEST_INTENT_LIMITS"),
            ("fail", WRITE_FAIL),
        ]
        .map(|(file, var)| (var, self.hook(file).to_string_lossy().into_owned()));
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut core = common::spawn_env("serve", &self.data, &self.locks, &[], &env);
        assert_eq!(core.grant_root, self.grant_root);
        core.store_moved = self.moved.clone();
        let hello = core.hello();
        assert!(hello.get("result").is_some(), "{hello}");
        self.core = Some(core);
        hello
    }

    fn send(&mut self, context: &str, method: &str, params: &str) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let payload = format!(
            r#"{{"type":"request","id":{id},"method":"{method}","params":{params},"context":{context}}}"#
        );
        let core = self.core.as_mut().expect("a core runs");
        core.send_raw(&common::raw_frame(1, payload.as_bytes()));
        core.response(id)
    }

    /// A request from main, its members as JSON text (a vector's numbers
    /// reach the core exactly as JS writes them).
    fn call(&mut self, method: &str, params: &str) -> Value {
        self.send(r#"{"caller":"shell"}"#, method, params)
    }

    fn result(&mut self, method: &str, params: &str) -> Value {
        let response = self.call(method, params);
        assert!(response.get("result").is_some(), "{method}: {response}");
        response["result"].clone()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.grant_root.join(name)
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.path(FILE)).unwrap_or_default()
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.grant_root)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

/// The views a fresh load gives (a step's `load`), read from a core that
/// main's file wasn't handed to.
fn check_load(reader: &mut Main, name: &str, load: &JsValue) {
    assert!(
        matches!(field(load, "reason"), JsValue::Null),
        "{name}: a step's file is never damaged"
    );
    let list = reader.result("intents.list", "{}");
    assert_eq!(list["intents"], wire(field(load, "list")), "{name}: list");
    let held: Vec<Value> = reader.result("intents.held", "{}")["intents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["intentId"].clone())
        .collect();
    assert_eq!(Value::from(held), wire(field(load, "held")), "{name}: held");
    for entry in items(field(load, "by_key")) {
        let key = JsValue::Object(vec![("key".into(), field(entry, "key").clone())]);
        let found = reader.result("intents.by_key", &key.stringify());
        assert_eq!(
            found["intent"]
                .get("intentId")
                .cloned()
                .unwrap_or(Value::Null),
            wire(field(entry, "id")),
            "{name}: by_key"
        );
    }
    for entry in items(field(load, "held_nonces")) {
        let params = format!(
            r#"{{"chain_id":{},"sender":{}}}"#,
            field(entry, "chain_id").stringify(),
            field(entry, "sender").stringify()
        );
        let nonces = reader.result("intents.held_nonces", &params);
        assert_eq!(
            nonces["nonces"],
            wire(field(entry, "nonces")),
            "{name}: held_nonces"
        );
    }
    let views = list["intents"].as_array().unwrap().clone();
    for (view, refusal) in views.iter().zip(items(field(load, "void_refusal"))) {
        let params = json!({ "intent_id": view["intentId"], "run": LOAD_RUN }).to_string();
        let ours = reader.result("intents.void_refusal", &params);
        assert_eq!(ours["refusal"], wire(refusal), "{name}: void_refusal");
    }
    let usage = reader.result("intents.usage", "{}")["usage"].clone();
    let theirs = wire(field(load, "usage"));
    for key in ["owed", "budget", "limit"] {
        assert_eq!(usage[key], theirs[key], "{name}: usage.{key}");
    }
    // Main's file as it is: nothing compacted before the name.
    assert_eq!(
        usage["file"],
        json!(reader.bytes().len()),
        "{name}: usage.file"
    );
}

/// One step through the moved core: its refusal, if any.
fn step(main: &mut Main, name: &str, step: &JsValue, limits: &mut JsValue) -> Option<Value> {
    let op = field(step, "op").as_str().unwrap();
    let run = field(step, "run").as_str().unwrap();
    let call = field(step, "call");
    main.set("clock", &field(step, "at").stringify());
    let uuids: Vec<&str> = items(field(step, "uuids"))
        .iter()
        .map(|u| u.as_str().unwrap())
        .collect();
    main.set("ids", &uuids.join("\n"));
    let (method, params) = match op {
        "restart" => {
            if let JsValue::Object(_) = field(field(step, "args"), "limits") {
                *limits = field(field(step, "args"), "limits").clone();
            }
            main.set("limits", &limits.stringify());
            main.start();
            // The load, at the first request, as the reference's at start.
            main.result("intents.get", r#"{"intent_id":"none-such-id"}"#);
            return None;
        }
        "compact" => ("intents.compact".to_owned(), "{}".to_owned()),
        "withdrawOrigin" => ("intents.withdraw_origin".to_owned(), members(call, None)),
        "commit" | "handoff" | "outcome" | "settle" | "void" | "retire" | "track" => {
            (format!("intents.{op}"), members(call, Some(run)))
        }
        other => panic!("unknown op {other}"),
    };
    let response = main.call(&method, &params);
    if response.get("error").is_some() {
        return Some(response);
    }
    let result = &response["result"];
    match op {
        "withdrawOrigin" => assert_eq!(result["withdrawn"], wire(field(call, "result")), "{name}"),
        "handoff" => assert_eq!(result["handoff"], wire(field(call, "result")), "{name}"),
        "compact" => assert_eq!(result, &json!({}), "{name}"),
        _ => {
            let id = &result["intent"]["intentId"];
            let get = main.result("intents.get", &json!({ "intent_id": id }).to_string());
            assert_eq!(
                result["intent"], get["intent"],
                "{name}: a write answers get"
            );
        }
    }
    None
}

/// Every step of every run, over the wire: the refusal (code and message),
/// the file byte for byte (so each line's `run` is main's), and the live
/// views; and after each step, a core main's file wasn't handed to reads
/// it as a fresh load does.
#[test]
fn every_vector_step_through_the_daemon() {
    let vectors = intents();
    let (mut refused, mut type_errors, mut restarts) = (0, 0, 0);
    for run in items(field(&vectors, "runs")) {
        let run_name = field(run, "name").as_str().unwrap();
        let mut limits = match field(run, "limits") {
            JsValue::Object(_) => field(run, "limits").clone(),
            _ => JsValue::Object(vec![]),
        };
        let mut main = Main::new(&["intents"]);
        main.set("limits", &limits.stringify());
        let hello = main.start();
        assert_eq!(hello["result"]["store_moved"], json!(["intents"]));
        let mut reader = Main::new(&[]);
        reader.start();
        for (i, s) in items(field(run, "steps")).iter().enumerate() {
            let name = format!("{run_name} step {i} ({})", field(s, "op").as_str().unwrap());
            restarts += usize::from(field(s, "op").as_str() == Some("restart"));
            let error = step(&mut main, &name, s, &mut limits);
            match (error, field(s, "refusal")) {
                (None, JsValue::Null) => {}
                (Some(e), JsValue::Null) => panic!("{name}: refused {e}"),
                (None, theirs) => panic!("{name}: written, refused as {theirs:?}"),
                (Some(e), theirs) => {
                    refused += 1;
                    let theirs_code = field(theirs, "code").as_str().unwrap();
                    assert_eq!(code(&e), "invalid_argument", "{name}: {e}");
                    if theirs_code.is_empty() {
                        // JavaScript's own TypeError: the members' check.
                        type_errors += 1;
                        assert_eq!(e["error"]["message"], "Invalid parameters", "{name}");
                        assert!(e["error"].get("data").is_none(), "{name}: {e}");
                    } else {
                        assert_eq!(e["error"]["data"]["code"], theirs_code, "{name}: {e}");
                        assert_eq!(
                            e["error"]["message"],
                            wire(field(theirs, "message")),
                            "{name}"
                        );
                    }
                }
            }
            assert_eq!(
                String::from_utf8(main.bytes()).unwrap(),
                String::from_utf8(lines(items(field(s, "records")))).unwrap(),
                "{name}: the file"
            );
            let live = field(s, "live");
            if !matches!(live, JsValue::Null) {
                let list = main.result("intents.list", "{}");
                assert_eq!(list["intents"], wire(field(live, "list")), "{name}: list");
                // Asked only where the reference asked: usage sizes snapshots.
                let usage = main.result("intents.usage", "{}");
                assert_eq!(usage["usage"], wire(field(live, "usage")), "{name}: usage");
                let run_id = field(s, "run").as_str().unwrap();
                let views = list["intents"].as_array().unwrap().clone();
                for (view, refusal) in views.iter().zip(items(field(live, "void_refusal"))) {
                    let params = json!({ "intent_id": view["intentId"], "run": run_id });
                    let ours = main.result("intents.void_refusal", &params.to_string());
                    assert_eq!(ours["refusal"], wire(refusal), "{name}: void_refusal");
                }
            }
            std::fs::write(reader.path(FILE), main.bytes()).unwrap();
            reader.set("limits", &limits.stringify());
            check_load(&mut reader, &name, field(s, "load"));
        }
    }
    assert!(refused >= 30, "{refused} refusals");
    assert_eq!(type_errors, 3, "the reference's TypeErrors");
    assert!(restarts >= 9, "{restarts} restarts");
}

/// Replays a run's first `upto` steps on a moved core.
fn replay(run_name: &str, upto: usize) -> (Main, Vec<JsValue>) {
    let vectors = intents();
    let run = items(field(&vectors, "runs"))
        .iter()
        .find(|r| field(r, "name").as_str() == Some(run_name))
        .unwrap()
        .clone();
    let steps = items(field(&run, "steps")).to_vec();
    let mut limits = match field(&run, "limits") {
        JsValue::Object(_) => field(&run, "limits").clone(),
        _ => JsValue::Object(vec![]),
    };
    let mut main = Main::new(&["intents"]);
    main.set("limits", &limits.stringify());
    main.start();
    for s in &steps[..upto] {
        step(&mut main, run_name, s, &mut limits);
    }
    (main, steps)
}

fn failed_write(response: &Value) {
    assert_eq!(code(response), "storage", "{response}");
    assert_eq!(
        response["error"]["message"],
        "Could not save the wallet's payment record."
    );
    assert_eq!(response["error"]["data"]["code"], "INTENT_WRITE_FAILED");
    assert_eq!(response["error"]["data"]["store"], "intents");
}

/// A failed append (its write, its fsync) answers `INTENT_WRITE_FAILED`,
/// the file and the records as they were, and the next write goes
/// through. A cut back that fails too leaves the journal broken: every
/// write fails until the core opens it again.
#[test]
fn a_failed_append_changes_nothing() {
    let (mut main, steps) = replay("lifecycle", 2);
    let handoff = &steps[2];
    assert_eq!(field(handoff, "op").as_str(), Some("handoff"));
    let params = members(field(handoff, "call"), field(handoff, "run").as_str());
    let before = main.bytes();
    let list = main.result("intents.list", "{}");
    for fail in ["intents:write", "intents:fsync"] {
        main.set("fail", fail);
        main.set("ids", "00000000-0000-4000-8000-0000000000aa");
        failed_write(&main.call("intents.handoff", &params));
        assert_eq!(main.bytes(), before, "{fail}");
        assert_eq!(main.result("intents.list", "{}"), list, "{fail}");
    }
    main.set("fail", "intents:fsync\nintents:truncate");
    failed_write(&main.call("intents.handoff", &params));
    main.set("fail", "");
    failed_write(&main.call("intents.handoff", &params));
    assert_eq!(main.result("intents.list", "{}"), list);
    // Opened again by a new core: the half-written line is cut off.
    main.start();
    main.set("ids", "00000000-0000-4000-8000-0000000000ab");
    main.result("intents.handoff", &params);
    let records = std::fs::read_to_string(main.path(FILE)).unwrap();
    assert!(records.ends_with("\n") && records.contains("0000000000ab"));
}

/// A commit that needs the file compacted first: a failed compaction
/// answers `INTENT_WRITE_FAILED` with nothing changed, and the same commit
/// then compacts and writes as the reference does.
#[test]
fn a_failed_admission_compaction_changes_nothing() {
    let (mut main, steps) = replay("a commit that needs room", 13);
    let commit = &steps[13];
    let before = main.bytes();
    let list = main.result("intents.list", "{}");
    let params = members(field(commit, "call"), field(commit, "run").as_str());
    let ids = items(field(commit, "uuids"))[0]
        .as_str()
        .unwrap()
        .to_owned();
    main.set("clock", &field(commit, "at").stringify());
    for fail in ["intents:write", "intents:fsync", "intents:rename"] {
        main.set("fail", fail);
        main.set("ids", &ids);
        failed_write(&main.call("intents.commit", &params));
        assert_eq!(main.bytes(), before, "{fail}");
        assert_eq!(main.result("intents.list", "{}"), list, "{fail}");
    }
    main.set("fail", "");
    main.set("ids", &ids);
    main.result("intents.commit", &params);
    assert_eq!(main.bytes(), lines(items(field(commit, "records"))));
}

/// `withdraw_origin` whose compaction fails puts the origin back; a void
/// whose compaction fails still answers the void, its line appended.
#[test]
fn compactions_that_fail_after_a_change() {
    let (mut main, steps) = replay("void and recovery", 8);
    let held = main.result("intents.held", "{}")["intents"]
        .as_array()
        .unwrap()
        .clone();
    let with_origin = held
        .iter()
        .find(|v| v["context"]["origin"].is_string())
        .expect("a held intent with a site")["intentId"]
        .clone();
    let params = json!({ "intent_id": with_origin }).to_string();
    main.set("fail", "intents:rename");
    let response = main.call("intents.withdraw_origin", &params);
    assert_eq!(code(&response), "storage", "{response}");
    let get = main.result("intents.get", &params);
    assert!(get["intent"]["context"]["origin"].is_string(), "{get}");
    main.set("fail", "");
    assert_eq!(
        main.result("intents.withdraw_origin", &params)["withdrawn"],
        true
    );
    let get = main.result("intents.get", &params);
    assert_eq!(get["intent"]["context"]["origin"], Value::Null);
    // A void (the lifecycle's own) with its compaction failing.
    let (mut main, steps2) = replay("refusals", 8);
    let void = steps2
        .iter()
        .position(|s| {
            field(s, "op").as_str() == Some("void") && matches!(field(s, "refusal"), JsValue::Null)
        })
        .unwrap();
    assert_eq!(void, 8, "the refusals run's void");
    let s = &steps2[void];
    let before = main.bytes();
    main.set("fail", "intents:rename");
    main.set("clock", &field(s, "at").stringify());
    let answer = main.result(
        "intents.void",
        &members(field(s, "call"), field(s, "run").as_str()),
    );
    assert_eq!(answer["intent"]["state"], "voided");
    let after = String::from_utf8(main.bytes()).unwrap();
    assert!(after.starts_with(std::str::from_utf8(&before).unwrap()));
    assert!(after[before.len()..].contains(r#""type":"void""#));
    drop(steps);
}

/// Before `intents` is named: every write answers `not_moved`, whatever
/// its members, and nothing in `grant_root` changes (a damaged file and a
/// torn tail included); reads are served, a damaged file reading as empty.
/// Not echoed.
#[test]
fn before_the_name_main_writes_it() {
    let mut main = Main::new(&["vault_meta"]);
    let torn = b"{\"v\":1,\"sha256\":\"00\",\"record\":{}}\n{\"v\":1,\"sha";
    std::fs::write(main.path(FILE), torn).unwrap();
    let hello = main.start();
    let echo = hello["result"]["store_moved"].as_array().unwrap();
    assert!(!echo.contains(&json!("intents")), "{hello}");
    let names = main.names();
    for method in WRITES {
        for params in [r#"{}"#, r#"{"intent_id":7}"#, r#"[1]"#] {
            let response = main.call(method, params);
            assert_eq!(code(&response), "not_moved", "{method}: {response}");
            assert_eq!(response["error"]["data"]["store"], "intents");
        }
    }
    assert_eq!(main.names(), names);
    assert_eq!(main.bytes(), torn);
    assert_eq!(main.result("intents.list", "{}")["intents"], json!([]));
    assert_eq!(
        main.result("intents.usage", "{}")["usage"],
        json!({ "file": 0, "owed": 0, "budget": 0, "limit": 8388608 })
    );
    assert_eq!(main.bytes(), torn);
    assert_eq!(main.names(), names);
}

/// Every method is main's: the chrome and a page get `forbidden`, with the
/// store moved or not, and nothing is written.
#[test]
fn every_method_is_mains() {
    for moved in [&["intents"][..], &[][..]] {
        let mut main = Main::new(moved);
        main.start();
        for method in WRITES.iter().chain(&READS) {
            for context in [
                r#"{"caller":"chrome"}"#,
                r#"{"caller":"page","page":{"origin":"https://a.example","top_origin":"https://a.example","frame":1,"navigation":1,"agent":false}}"#,
            ] {
                let response = main.send(context, method, "{}");
                assert_eq!(
                    code(&response),
                    "forbidden",
                    "{method} {context}: {response}"
                );
            }
        }
        assert!(!main.path(FILE).exists());
    }
}

/// Members are checked before the rules: an unknown member, a missing
/// one, or one of another JSON type than main passes is `invalid_argument`
/// ("Invalid parameters", no `data.code`), and nothing is written; `run`
/// must have the reference's id form.
#[test]
fn members_are_checked_first() {
    let mut main = Main::new(&["intents"]);
    main.start();
    let run = r#""00000000-0000-4000-8000-000000000001""#;
    let id = r#""00000000-0000-4000-8000-000000000002""#;
    let bad = [
        ("intents.handoff", format!(r#"{{"intent_id":{id}}}"#)),
        (
            "intents.handoff",
            format!(r#"{{"run":"short","intent_id":{id}}}"#),
        ),
        (
            "intents.handoff",
            format!(r#"{{"run":7,"intent_id":{id}}}"#),
        ),
        (
            "intents.handoff",
            format!(r#"{{"run":{run},"intent_id":{{"toString":1}}}}"#),
        ),
        (
            "intents.handoff",
            format!(r#"{{"run":{run},"intent_id":{id},"extra":1}}"#),
        ),
        (
            "intents.handoff",
            format!(r#"{{"run":{run},"intentId":{id}}}"#),
        ),
        (
            "intents.void",
            format!(r#"{{"run":{run},"intent_id":{id}}}"#),
        ),
        (
            "intents.void",
            format!(r#"{{"run":{run},"intent_id":{id},"lock":"yes"}}"#),
        ),
        (
            "intents.settle",
            format!(r#"{{"run":{run},"intent_id":{id},"label":"paid","block":1,"hashes":"abc"}}"#),
        ),
        (
            "intents.retire",
            format!(r#"{{"run":{run},"intent_id":{id},"block":1,"hashes":[{{}}],"lock":true}}"#),
        ),
        (
            "intents.retire",
            format!(r#"{{"run":{run},"intent_id":{id},"block":1,"lock":true}}"#),
        ),
        (
            "intents.commit",
            format!(
                r#"{{"run":{run},"chain_id":"1","sender":"0x","nonce":0,"hash":"0x","raw":"0x","via":"original"}}"#
            ),
        ),
        ("intents.get", r#"{"intent_id":2}"#.to_owned()),
        ("intents.held_nonces", r#"{"chain_id":1}"#.to_owned()),
        ("intents.void_refusal", format!(r#"{{"intent_id":{id}}}"#)),
        ("intents.list", r#"{"all":true}"#.to_owned()),
        ("intents.usage", "[]".to_owned()),
    ];
    for (method, params) in bad {
        let response = main.call(method, &params);
        assert_eq!(
            code(&response),
            "invalid_argument",
            "{method} {params}: {response}"
        );
        assert_eq!(
            response["error"]["message"], "Invalid parameters",
            "{params}"
        );
        assert!(
            response["error"].get("data").is_none(),
            "{params}: {response}"
        );
    }
    assert!(!main.path(FILE).exists());
    // A refusal of the rules carries the reference's code.
    let response = main.call(
        "intents.void_refusal",
        &format!(r#"{{"intent_id":"not-an-intent-01","run":{run}}}"#),
    );
    assert_eq!(
        response["error"]["data"]["code"], "INTENT_UNKNOWN",
        "{response}"
    );
    assert_eq!(
        response["error"]["message"],
        "Unknown wallet intent not-an-intent-01"
    );
}

/// Each damaged file of the vectors, once moved: set aside as
/// `<file>.corrupt-<ms>` with the reference's reason logged, the store
/// empty; a file the reference loads stays.
#[test]
fn a_damaged_file_is_set_aside() {
    let vectors = intents();
    let mut set_aside = 0;
    for case in items(field(&vectors, "damaged")) {
        let name = field(case, "name").as_str().unwrap();
        let mut main = Main::new(&["intents"]);
        let text = lines(items(field(case, "records")));
        std::fs::write(main.path(FILE), &text).unwrap();
        main.set("clock", "1763000009999");
        main.start();
        let list = main.result("intents.list", "{}");
        match field(case, "reason") {
            JsValue::Null => {
                assert!(main.path(FILE).exists(), "{name}");
                assert!(!main.path(&format!("{FILE}.corrupt-1763000009999")).exists());
            }
            reason => {
                set_aside += 1;
                assert_eq!(list["intents"], json!([]), "{name}");
                assert!(!main.path(FILE).exists(), "{name}");
                let aside = main.path(&format!("{FILE}.corrupt-1763000009999"));
                assert_eq!(std::fs::read(aside).unwrap(), text, "{name}");
                let core = main.core.as_mut().unwrap();
                core.close_stdin();
                core.exit_code(std::time::Duration::from_secs(10));
                let log = core.stderr();
                let reason = serde_json::to_string(reason.as_str().unwrap()).unwrap();
                assert!(log.contains(&reason), "{name}: {reason} not in {log}");
            }
        }
    }
    assert!(set_aside >= 60, "{set_aside}");
}
