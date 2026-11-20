//! The pending Safe transactions in the core (design 0013, "Pending Safe
//! transactions"; PRF-5f): vectors/stores.json's `safe_pending`, which the
//! pinned reference's pending-store.js produced, replayed over the wire,
//! each file byte for byte; main's alone; reads before `safe_pending` is in
//! `store_moved`, and writes `not_moved` with nothing touched; an
//! unreadable file set aside once moved; a failed write reported with the
//! file as it was; the 1 MiB bound.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};

use fc_json::JsValue;
use serde_json::{Value, json};

const FILE: &str = "safe-pending.json";
const ASIDE: &str = "safe-pending.json.unreadable";
/// A temp file of fc-store's durable write (`.<name>.<pid>.<n>.tmp`).
const TEMP: &str = ".safe-pending.json.4242.1.tmp";
const MAX_FILE_BYTES: usize = 1 << 20;
const METHODS: [&str; 4] = [
    "safe_pending.get",
    "safe_pending.set",
    "safe_pending.clear",
    "safe_pending.list",
];
const WRITE_FAIL: &str = "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL";

static UNDEFINED: JsValue = JsValue::Undefined;

/// A profile and the core running on it.
struct Main {
    _root: tempfile::TempDir,
    data: PathBuf,
    locks: PathBuf,
    grant_root: PathBuf,
    core: Option<common::Core>,
    next_id: u64,
    /// The hello's `store_moved`.
    moved: Vec<&'static str>,
}

impl Main {
    fn new(moved: &[&'static str]) -> Main {
        let (root, data, locks) = common::dirs();
        let grant_root = root.path().join("userData");
        std::fs::create_dir_all(&grant_root).unwrap();
        Main {
            _root: root,
            data,
            locks,
            grant_root,
            core: None,
            next_id: 10,
            moved: moved.to_vec(),
        }
    }

    fn start(&mut self, env: &[(&str, &str)]) -> Value {
        self.core = None;
        let mut core = common::spawn_env("serve", &self.data, &self.locks, &[], env);
        assert_eq!(core.grant_root, self.grant_root);
        core.store_moved = self.moved.clone();
        let hello = core.hello();
        assert!(hello.get("result").is_some(), "{hello}");
        self.core = Some(core);
        hello
    }

    fn call_as(&mut self, context: Value, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let core = self.core.as_mut().expect("a core runs");
        core.send(&json!({
            "type": "request", "id": id, "method": method, "params": params, "context": context,
        }));
        core.response(id)
    }

    /// A request from main whose parameters are JSON text: a vector's
    /// numbers reach the core exactly as JS writes them.
    fn call_text(&mut self, method: &str, params: &str) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let payload = format!(
            r#"{{"type":"request","id":{id},"method":"{method}","params":{params},"context":{{"caller":"shell"}}}}"#
        );
        let core = self.core.as_mut().expect("a core runs");
        core.send_raw(&common::raw_frame(1, payload.as_bytes()));
        core.response(id)
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.call_as(json!({ "caller": "shell" }), method, params)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.grant_root.join(name)
    }

    /// The file's bytes, or none.
    fn bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.path(FILE)).ok()
    }

    fn write(&self, bytes: &[u8]) {
        std::fs::write(self.path(FILE), bytes).unwrap();
    }

    fn clean(&self) {
        for name in [FILE, ASIDE] {
            let _ = std::fs::remove_file(self.path(name));
        }
    }

    /// The names in `grant_root`, sorted.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.grant_root)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

/// The file's identity: a write replaces it (a new inode); none else does.
#[cfg(unix)]
fn identity(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.ino())
}

#[cfg(not(unix))]
fn identity(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|_| 0)
}

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("")
}

fn result(reply: &Value) -> &Value {
    reply
        .get("result")
        .unwrap_or_else(|| panic!("no result: {reply}"))
}

fn section() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/stores.json");
    let text = std::fs::read_to_string(path).unwrap();
    fc_json::parse(&text)
        .unwrap()
        .get("safe_pending")
        .unwrap()
        .clone()
}

fn field<'a>(value: &'a JsValue, key: &str) -> &'a JsValue {
    value.get(key).unwrap_or(&UNDEFINED)
}

fn items(value: &JsValue) -> &[JsValue] {
    value.as_array().unwrap()
}

fn text(value: &JsValue) -> &str {
    value.as_str().unwrap()
}

/// A vector's value as the JSON main sends.
fn json_of(value: &JsValue) -> Value {
    serde_json::from_str(&value.stringify()).unwrap()
}

/// Whether a reply's value is the vector's, in the same key order. Both
/// go through serde_json's reading once, from the core's text and from
/// JS's, so a number matches only where the two texts read alike.
fn same(reply: &Value, expected: &JsValue) -> bool {
    serde_json::to_string(reply).unwrap() == serde_json::to_string(&json_of(expected)).unwrap()
}

fn bytes_of(case: &JsValue) -> Vec<u8> {
    if let Some(hex) = case.get("hex") {
        let hex = text(hex);
        return (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
    }
    if let Some(fill) = case.get("fill") {
        let (open, close) = (text(field(fill, "open")), text(field(fill, "close")));
        let JsValue::Number(bytes) = field(fill, "bytes") else {
            panic!("bytes")
        };
        let pad = text(field(fill, "char")).repeat(*bytes as usize - open.len() - close.len());
        return format!("{open}{pad}{close}").into_bytes();
    }
    text(field(case, "text")).as_bytes().to_vec()
}

/// What the reference writes after `setPending(7, { a: 1 })` over `{}`.
const SET_OVER_EMPTY: &str = "{\n  \"7\": {\n    \"a\": 1\n  }\n}";

/// Every run's steps over the wire, from its start text: the reference's
/// answers, a write exactly where it wrote (a new file), the file's text
/// byte for byte after each, and no temp file left.
#[test]
fn every_vector_step_through_the_core() {
    let mut main = Main::new(&["safe_pending"]);
    // A temp file of an earlier core's write goes at the hello.
    std::fs::write(main.path(TEMP), b"{}").unwrap();
    let hello = main.start(&[]);
    assert_eq!(hello["result"]["store_moved"], json!(["safe_pending"]));
    assert!(!main.path(TEMP).exists());
    let section = section();
    let mut steps = 0;
    for run in items(field(&section, "runs")) {
        let id = text(field(run, "id"));
        main.clean();
        if let JsValue::String(start) = field(run, "start") {
            main.write(start.as_str().as_bytes());
        }
        for (n, step) in items(field(run, "steps")).iter().enumerate() {
            let at = format!("{id} step {n}");
            let before = identity(&main.path(FILE));
            let args = items(field(step, "args"));
            let op = text(field(step, "op"));
            let reply = match op {
                "get" | "clear" => main.call_text(
                    &format!("safe_pending.{op}"),
                    &format!(r#"{{"index":{}}}"#, args[0].stringify()),
                ),
                "set" => main.call_text(
                    "safe_pending.set",
                    &format!(
                        r#"{{"index":{},"entry":{}}}"#,
                        args[0].stringify(),
                        args[1].stringify()
                    ),
                ),
                "list" => main.call("safe_pending.list", json!({})),
                other => panic!("{at}: {other}"),
            };
            let answer = result(&reply);
            let wrote = matches!(field(step, "wrote"), JsValue::Bool(true));
            match op {
                "get" => assert!(
                    same(&answer["entry"], field(step, "result")),
                    "{at}: {reply}"
                ),
                "list" => assert!(
                    same(&answer["indices"], field(step, "result")),
                    "{at}: {reply}"
                ),
                "set" => assert_eq!(answer, &json!({ "durable": true }), "{at}"),
                _ => assert_eq!(
                    answer,
                    &json!({ "cleared": wrote, "durable": true }),
                    "{at}"
                ),
            }
            let expected = match field(step, "text") {
                JsValue::Null => None,
                t => Some(text(t).as_bytes().to_vec()),
            };
            assert_eq!(main.bytes(), expected, "{at}: the file");
            let after = identity(&main.path(FILE));
            if cfg!(unix) {
                assert_eq!(before != after, wrote, "{at}: wrote");
            }
            assert!(
                main.names().iter().all(|n| n == FILE),
                "{at}: {:?}",
                main.names()
            );
            steps += 1;
        }
    }
    assert!(steps >= 70);
}

/// Each malformed file once moved: one the core parses answers, and is
/// set, as the reference does (past the bound refused, the file as it
/// was); an unreadable one is renamed aside as it is, reads as empty, and
/// the next set writes what the reference writes over `{}`.
#[test]
fn malformed_files_once_moved() {
    let mut main = Main::new(&["safe_pending"]);
    main.start(&[]);
    let section = section();
    for case in items(field(&section, "malformed")) {
        let id = text(field(case, "id"));
        main.clean();
        let bytes = bytes_of(case);
        main.write(&bytes);
        let listed = main.call("safe_pending.list", json!({}));
        let index = json_of(field(case, "index"));
        let set = field(case, "set");
        match text(field(case, "core")) {
            "unreadable" => {
                assert_eq!(result(&listed)["indices"], json!([]), "{id}");
                assert_eq!(main.bytes(), None, "{id}");
                assert_eq!(std::fs::read(main.path(ASIDE)).unwrap(), bytes, "{id}");
                let reply = main.call(
                    "safe_pending.set",
                    json!({ "index": 7, "entry": { "a": 1 } }),
                );
                assert_eq!(result(&reply)["durable"], true, "{id}");
                assert_eq!(main.bytes().unwrap(), SET_OVER_EMPTY.as_bytes(), "{id}");
            }
            "parsed" => {
                let expected = field(field(case, "listed"), "result");
                assert!(
                    same(&result(&listed)["indices"], expected),
                    "{id}: {listed}"
                );
                assert_eq!(main.bytes().unwrap(), bytes, "{id}: read only");
                // A filled file's entry is a MiB: its reply would be in
                // fragments; the codec's replay checks it.
                if case.get("fill").is_none() && index.as_u64().is_some() {
                    let got = main.call("safe_pending.get", json!({ "index": index }));
                    let expected = field(field(case, "got"), "result");
                    assert!(same(&result(&got)["entry"], expected), "{id}: {got}");
                }
                let before = identity(&main.path(FILE));
                let reply = main.call(
                    "safe_pending.set",
                    json!({ "index": 7, "entry": { "a": 1 } }),
                );
                match text(field(set, "core")) {
                    "written" => {
                        assert_eq!(result(&reply)["durable"], true, "{id}");
                        let written = main.bytes().unwrap();
                        match set.get("text") {
                            Some(t) => assert_eq!(written, text(t).as_bytes(), "{id}"),
                            None => {
                                let JsValue::Number(n) = field(set, "bytes") else {
                                    panic!("{id}: bytes")
                                };
                                assert_eq!(written.len(), *n as usize, "{id}");
                            }
                        }
                    }
                    "refused" => {
                        assert_eq!(code(&reply), "invalid_argument", "{id}: {reply}");
                        assert_eq!(main.bytes().unwrap(), bytes, "{id}");
                        assert_eq!(identity(&main.path(FILE)), before, "{id}");
                    }
                    other => panic!("{id}: {other}"),
                }
            }
            other => panic!("{id}: {other}"),
        }
        assert!(
            main.names().iter().all(|n| n == FILE || n == ASIDE),
            "{id}: {:?}",
            main.names()
        );
    }
}

/// Before `safe_pending` is named: the reads are served from main's file,
/// an unreadable one reading as empty and staying where it is; every write
/// answers `not_moved` (`data.store`), whatever its parameters, and
/// nothing in `grant_root` is written, renamed or removed. Not echoed.
#[test]
fn before_the_name_main_writes_it() {
    let mut main = Main::new(&["vault_meta"]);
    // Main's file: even a temp file of the core's naming stays.
    std::fs::write(main.path(TEMP), b"{}").unwrap();
    let hello = main.start(&[]);
    assert!(main.path(TEMP).exists());
    let echo = hello["result"]["store_moved"].as_array().unwrap();
    assert!(!echo.contains(&json!("safe_pending")), "{hello}");
    let writes = [
        (
            "safe_pending.set",
            json!({ "index": 7, "entry": { "a": 1 } }),
        ),
        ("safe_pending.set", json!({ "index": "bad" })),
        ("safe_pending.clear", json!({ "index": 1 })),
        ("safe_pending.clear", json!({})),
    ];
    let not_moved = |main: &mut Main| {
        for (method, params) in &writes {
            let reply = main.call(method, params.clone());
            assert_eq!(code(&reply), "not_moved", "{method}: {reply}");
            assert_eq!(reply["error"]["data"]["store"], "safe_pending");
        }
    };
    // No file: none is made.
    let names = main.names();
    not_moved(&mut main);
    assert_eq!(main.bytes(), None);
    assert_eq!(main.names(), names);
    let section = section();
    for case in items(field(&section, "malformed")) {
        let id = text(field(case, "id"));
        main.clean();
        let bytes = bytes_of(case);
        main.write(&bytes);
        let before = identity(&main.path(FILE));
        let names = main.names();
        let listed = main.call("safe_pending.list", json!({}));
        if text(field(case, "core")) == "parsed" {
            let expected = field(field(case, "listed"), "result");
            assert!(
                same(&result(&listed)["indices"], expected),
                "{id}: {listed}"
            );
        } else {
            assert_eq!(result(&listed)["indices"], json!([]), "{id}");
            let got = main.call("safe_pending.get", json!({ "index": 1 }));
            assert_eq!(result(&got)["entry"], Value::Null, "{id}");
        }
        not_moved(&mut main);
        assert_eq!(main.bytes().unwrap(), bytes, "{id}");
        assert_eq!(identity(&main.path(FILE)), before, "{id}");
        assert_eq!(main.names(), names, "{id}");
    }
    // A run's reads answer from main's file as the reference does.
    let run = &items(field(&section, "runs"))[1];
    main.clean();
    main.write(text(field(run, "start")).as_bytes());
    for step in items(field(run, "steps")) {
        let args = items(field(step, "args"));
        match text(field(step, "op")) {
            "get" => {
                let reply = main.call("safe_pending.get", json!({ "index": json_of(&args[0]) }));
                assert!(same(&result(&reply)["entry"], field(step, "result")));
            }
            "list" => {
                let reply = main.call("safe_pending.list", json!({}));
                assert!(same(&result(&reply)["indices"], field(step, "result")));
            }
            _ => break,
        }
    }
}

/// Main's alone: the chrome and a page reach none of the four; the
/// parameters are checked.
#[test]
fn callers_and_parameters() {
    let mut main = Main::new(&["safe_pending"]);
    main.start(&[]);
    main.write(b"{\"1\":{\"a\":1}}");
    let page = json!({ "caller": "page", "page": {
        "origin": "https://app.example", "top_origin": "https://app.example",
        "frame": 1, "navigation": 1, "agent": false,
    } });
    for method in METHODS {
        for context in [json!({ "caller": "chrome" }), page.clone()] {
            let reply = main.call_as(context, method, json!({ "index": 1, "entry": { "b": 2 } }));
            assert_eq!(code(&reply), "forbidden", "{method}: {reply}");
        }
    }
    assert_eq!(main.bytes().unwrap(), b"{\"1\":{\"a\":1}}");
    for (method, params) in [
        ("safe_pending.get", json!({})),
        ("safe_pending.get", json!({ "index": "1" })),
        ("safe_pending.get", json!({ "index": -1 })),
        ("safe_pending.get", json!({ "index": 1.5 })),
        (
            "safe_pending.get",
            json!({ "index": 9_007_199_254_740_992u64 }),
        ),
        ("safe_pending.set", json!({ "index": 1 })),
        ("safe_pending.set", json!({ "entry": {} })),
        ("safe_pending.clear", json!({ "index": null })),
    ] {
        let reply = main.call(method, params.clone());
        assert_eq!(
            code(&reply),
            "invalid_argument",
            "{method} {params}: {reply}"
        );
    }
    let reply = main.call("safe_pending.get", json!(null));
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    assert_eq!(main.bytes().unwrap(), b"{\"1\":{\"a\":1}}");
    let reply = main.call("safe_pending.get", json!({ "index": 1 }));
    assert_eq!(result(&reply)["entry"], json!({ "a": 1 }));
}

/// A write that fails before its rename (the temp file's write, its fsync,
/// the rename) is reported (`storage`, `data.store`), the file as it was
/// and no temp file left; a failed directory flush after the rename leaves
/// the change, `durable: false`. A clear the same.
#[test]
fn a_failed_write_is_reported_with_the_store_unchanged() {
    let mut main = Main::new(&["safe_pending"]);
    let spec = main._root.path().join("write-fail");
    std::fs::write(&spec, "").unwrap();
    main.start(&[(WRITE_FAIL, spec.to_str().unwrap())]);
    let reply = main.call(
        "safe_pending.set",
        json!({ "index": 1, "entry": { "a": 1 } }),
    );
    assert_eq!(result(&reply)["durable"], true);
    let start = main.bytes().unwrap();
    for step in ["write", "fsync", "rename"] {
        // Another store's line fails nothing here.
        std::fs::write(&spec, format!("dapp:{step}\n")).unwrap();
        let reply = main.call(
            "safe_pending.set",
            json!({ "index": 2, "entry": { "s": step } }),
        );
        assert_eq!(result(&reply)["durable"], true, "{step}");
        let clear = main.call("safe_pending.clear", json!({ "index": 2 }));
        assert_eq!(result(&clear)["cleared"], true, "{step}");
        std::fs::write(&spec, format!("safe_pending:{step}\n")).unwrap();
        let before = identity(&main.path(FILE));
        for (method, params) in [
            (
                "safe_pending.set",
                json!({ "index": 2, "entry": { "b": 2 } }),
            ),
            (
                "safe_pending.set",
                json!({ "index": 1, "entry": { "b": 2 } }),
            ),
            ("safe_pending.clear", json!({ "index": 1 })),
        ] {
            let reply = main.call(method, params);
            assert_eq!(code(&reply), "storage", "{step} {method}: {reply}");
            assert_eq!(reply["error"]["data"]["store"], "safe_pending");
            assert_eq!(main.bytes().unwrap(), start, "{step} {method}");
            assert_eq!(identity(&main.path(FILE)), before, "{step} {method}");
            assert_eq!(main.names(), vec![FILE.to_owned()], "{step} {method}");
        }
        // A clear with nothing to clear writes nothing, and so can't fail.
        let reply = main.call("safe_pending.clear", json!({ "index": 9 }));
        assert_eq!(
            result(&reply),
            &json!({ "cleared": false, "durable": true })
        );
        let reply = main.call("safe_pending.get", json!({ "index": 1 }));
        assert_eq!(result(&reply)["entry"], json!({ "a": 1 }), "{step}");
    }
    std::fs::write(&spec, "safe_pending:flush\n").unwrap();
    let reply = main.call(
        "safe_pending.set",
        json!({ "index": 1, "entry": { "c": 3 } }),
    );
    assert_eq!(result(&reply)["durable"], false, "{reply}");
    assert_eq!(
        main.bytes().unwrap(),
        b"{\n  \"1\": {\n    \"c\": 3\n  }\n}"
    );
    let reply = main.call("safe_pending.clear", json!({ "index": 1 }));
    assert_eq!(
        result(&reply),
        &json!({ "cleared": true, "durable": false })
    );
    assert_eq!(main.bytes().unwrap(), b"{}");
}

/// An unreadable file whose set-aside fails: the reads answer empty, and
/// nothing writes the file (`storage`).
#[test]
fn an_unreadable_file_that_cannot_be_set_aside() {
    let mut main = Main::new(&["safe_pending"]);
    main.start(&[]);
    main.write(b"{\"1\": {");
    // A directory in the way of the rename.
    std::fs::create_dir(main.path(ASIDE)).unwrap();
    std::fs::write(main.path(ASIDE).join("x"), b"x").unwrap();
    let reply = main.call("safe_pending.list", json!({}));
    assert_eq!(result(&reply)["indices"], json!([]));
    let reply = main.call("safe_pending.get", json!({ "index": 1 }));
    assert_eq!(result(&reply)["entry"], Value::Null);
    for (method, params) in [
        ("safe_pending.set", json!({ "index": 1, "entry": {} })),
        ("safe_pending.clear", json!({ "index": 1 })),
    ] {
        let reply = main.call(method, params);
        assert_eq!(code(&reply), "storage", "{method}: {reply}");
    }
    assert_eq!(main.bytes().unwrap(), b"{\"1\": {");
    // Once the way is clear, it is set aside and the store starts empty.
    std::fs::remove_dir_all(main.path(ASIDE)).unwrap();
    let reply = main.call(
        "safe_pending.set",
        json!({ "index": 7, "entry": { "a": 1 } }),
    );
    assert_eq!(result(&reply)["durable"], true);
    assert_eq!(std::fs::read(main.path(ASIDE)).unwrap(), b"{\"1\": {");
    assert_eq!(main.bytes().unwrap(), SET_OVER_EMPTY.as_bytes());
}

/// The 1 MiB bound at a set (stores.json's `bound`, whose one-entry form
/// is past one request frame): over a file of one long entry, a set that
/// makes the file exactly 1 MiB is written; one byte more is refused
/// (`invalid_argument`), the file as it was.
#[test]
fn the_bound_holds_at_a_set() {
    let mut main = Main::new(&["safe_pending"]);
    main.start(&[]);
    let section = section();
    let bound = items(field(&section, "bound"));
    assert_eq!(text(field(&bound[0], "core")), "written");
    assert_eq!(text(field(&bound[1], "core")), "refused");
    // `{\n  "0": "<m>",\n  "1": "<n>"\n}` is m + n + 24 bytes.
    let n = MAX_FILE_BYTES - 1000;
    let long = format!("{{\"1\":\"{}\"}}", "y".repeat(n));
    for (m, written) in [(1000 - 24, true), (1000 - 23, false)] {
        main.write(long.as_bytes());
        let before = identity(&main.path(FILE));
        let reply = main.call(
            "safe_pending.set",
            json!({ "index": 0, "entry": "x".repeat(m) }),
        );
        if written {
            assert_eq!(result(&reply)["durable"], true);
            assert_eq!(main.bytes().unwrap().len(), MAX_FILE_BYTES);
            let reply = main.call("safe_pending.list", json!({}));
            assert_eq!(result(&reply)["indices"], json!([0, 1]));
        } else {
            assert_eq!(code(&reply), "invalid_argument", "{reply}");
            assert_eq!(main.bytes().unwrap(), long.as_bytes());
            assert_eq!(identity(&main.path(FILE)), before);
        }
    }
}
