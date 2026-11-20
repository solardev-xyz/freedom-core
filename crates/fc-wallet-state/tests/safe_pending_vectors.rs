//! Replays vectors/stores.json's `safe_pending`, which the pinned
//! reference's wallet/safe/pending-store.js produced: every step, from the
//! run's start text, gives the reference's answer, writes when it writes,
//! and leaves the same text byte for byte; each malformed file reads as the
//! design says, answering and setting as the reference does where the core
//! parses it; and the 1 MiB bound holds at a set.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_json::JsValue;
use fc_wallet_state::safe_pending::{MAX_FILE_BYTES, SafePending, Unreadable};

static UNDEFINED: JsValue = JsValue::Undefined;

fn section() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/stores.json");
    let text = std::fs::read_to_string(path).expect("vectors/stores.json");
    let vectors = fc_json::parse(&text).expect("stores.json parses");
    vectors.get("safe_pending").expect("safe_pending").clone()
}

fn field<'a>(value: &'a JsValue, key: &str) -> &'a JsValue {
    value.get(key).unwrap_or(&UNDEFINED)
}

fn items(value: &JsValue) -> &[JsValue] {
    value.as_array().expect("an array")
}

fn text(value: &JsValue) -> &str {
    value.as_str().expect("a string")
}

fn number(value: &JsValue) -> f64 {
    match value {
        JsValue::Number(n) => *n,
        other => panic!("not a number: {other:?}"),
    }
}

fn index(value: &JsValue) -> u64 {
    let n = number(value);
    assert!(n >= 0.0 && n.fract() == 0.0, "not an index: {n}");
    n as u64
}

fn list_value(store: &SafePending) -> JsValue {
    JsValue::Array(
        store
            .list()
            .into_iter()
            .map(|i| JsValue::Number(i as f64))
            .collect(),
    )
}

fn get_value(store: &SafePending, at: u64) -> JsValue {
    store.get(at).cloned().unwrap_or(JsValue::Null)
}

fn text_value(text: Option<String>) -> JsValue {
    text.map_or(JsValue::Null, |t| JsValue::string(t.as_str()))
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
        let open = text(field(fill, "open"));
        let close = text(field(fill, "close"));
        let bytes = number(field(fill, "bytes")) as usize;
        let pad = text(field(fill, "char")).repeat(bytes - open.len() - close.len());
        return format!("{open}{pad}{close}").into_bytes();
    }
    text(field(case, "text")).as_bytes().to_vec()
}

#[test]
fn runs() {
    let section = section();
    assert_eq!(
        number(field(&section, "max_file_bytes")) as usize,
        MAX_FILE_BYTES
    );
    let runs = items(field(&section, "runs"));
    assert!(runs.len() >= 6);
    let mut steps_seen = 0;
    for run in runs {
        let id = text(field(run, "id"));
        // The file as the core reads it at each request.
        let mut file: Option<String> = match field(run, "start") {
            JsValue::Null => None,
            start => Some(text(start).to_owned()),
        };
        for (n, step) in items(field(run, "steps")).iter().enumerate() {
            let at = format!("{id} step {n}");
            let mut store = match &file {
                Some(t) => SafePending::load(t.as_bytes()).unwrap(),
                None => SafePending::empty(),
            };
            let args = items(field(step, "args"));
            let op = text(field(step, "op"));
            let (result, wrote) = match op {
                "get" => (get_value(&store, index(&args[0])), false),
                "list" => (list_value(&store), false),
                "set" => {
                    store.set(index(&args[0]), args[1].clone()).unwrap();
                    (JsValue::Null, true)
                }
                "clear" => (JsValue::Null, store.clear(index(&args[0]))),
                other => panic!("{at}: unknown op {other}"),
            };
            assert_eq!(&result, field(step, "result"), "{at}: {op}");
            assert_eq!(
                JsValue::Bool(wrote),
                *field(step, "wrote"),
                "{at}: {op} wrote"
            );
            if wrote {
                file = Some(store.text());
            }
            assert_eq!(
                text_value(file.clone()),
                *field(step, "text"),
                "{at}: {op} text"
            );
            steps_seen += 1;
        }
    }
    assert!(steps_seen >= 70);
}

#[test]
fn malformed() {
    let section = section();
    let cases = items(field(&section, "malformed"));
    assert!(cases.len() >= 20);
    for case in cases {
        let id = text(field(case, "id"));
        let loaded = SafePending::load(&bytes_of(case));
        match text(field(case, "core")) {
            "unreadable" => {
                let reason = text(field(case, "reason"));
                assert_eq!(
                    loaded.map(|_| ()).map_err(Unreadable::reason),
                    Err(reason),
                    "{id}"
                );
            }
            "parsed" => {
                let mut store = loaded.unwrap_or_else(|e| panic!("{id}: {e}"));
                assert_eq!(
                    list_value(&store),
                    *field(field(case, "listed"), "result"),
                    "{id}: list"
                );
                let got = get_value(&store, index(field(case, "index")));
                let expected = field(field(case, "got"), "result");
                match expected.get("length") {
                    Some(length) if case.get("fill").is_some() => {
                        assert_eq!(
                            got.as_js_string().unwrap().utf16_len() as f64,
                            number(length),
                            "{id}"
                        )
                    }
                    _ => assert_eq!(&got, expected, "{id}: get"),
                }
                let set = field(case, "set");
                let entry = fc_json::parse(r#"{"a":1}"#).unwrap();
                match text(field(set, "core")) {
                    "written" => {
                        store.set(7, entry).unwrap();
                        let written = store.text();
                        match set.get("text") {
                            Some(t) => assert_eq!(written, text(t), "{id}: set text"),
                            None => assert_eq!(
                                written.len() as f64,
                                number(field(set, "bytes")),
                                "{id}: set bytes"
                            ),
                        }
                    }
                    "refused" => {
                        let before = store.clone();
                        assert_eq!(store.set(7, entry), Err(Unreadable::TooLarge), "{id}");
                        assert_eq!(store, before, "{id}");
                    }
                    other => panic!("{id}: {other}"),
                }
            }
            other => panic!("{id}: unknown verdict {other}"),
        }
    }
}

#[test]
fn bound() {
    let section = section();
    let cases = items(field(&section, "bound"));
    assert_eq!(cases.len(), 2);
    for case in cases {
        let id = text(field(case, "id"));
        let entry = field(case, "entry");
        let length = number(field(entry, "length")) as usize;
        let value = JsValue::string(text(field(entry, "char")).repeat(length).as_str());
        let mut store = SafePending::empty();
        match text(field(case, "core")) {
            "written" => {
                store.set(index(field(case, "index")), value).unwrap();
                assert_eq!(
                    store.text().len() as f64,
                    number(field(case, "bytes")),
                    "{id}"
                );
            }
            "refused" => {
                assert_eq!(
                    store.set(index(field(case, "index")), value),
                    Err(Unreadable::TooLarge),
                    "{id}"
                );
                assert_eq!(store, SafePending::empty(), "{id}");
            }
            other => panic!("{id}: {other}"),
        }
    }
}
