//! Replays vectors/stores.json's `rpc_api_keys` (design 0013, PRF-5h),
//! generated from the stores reference's own `rpc-api-key-store.js`
//! through its `rpc-manager.js`: each run's steps through [`KeysFile`],
//! byte for byte, as the core writes `rpc-api-keys.json` with no key store,
//! with the keys the reference reads back after each; and each malformed
//! file's reading. Where the core deliberately differs, the vector records
//! the reference's behaviour and a test here asserts the core's, naming its
//! Deviations row.

use fc_json::JsValue;

use super::*;

static UNDEFINED: JsValue = JsValue::Undefined;

fn section() -> JsValue {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/stores.json");
    let text = std::fs::read_to_string(path).expect("vectors/stores.json");
    let all = fc_json::parse(&text).expect("stores.json parses");
    all.get("rpc_api_keys")
        .expect("an rpc_api_keys section")
        .clone()
}

fn field<'a>(value: &'a JsValue, key: &str) -> &'a JsValue {
    value.get(key).unwrap_or(&UNDEFINED)
}

fn text<'a>(value: &'a JsValue, key: &str) -> &'a str {
    field(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("{key}: not a string"))
}

/// A string member, `None` where it is null.
fn maybe<'a>(value: &'a JsValue, key: &str) -> Option<&'a str> {
    match field(value, key) {
        JsValue::Null => None,
        other => Some(other.as_str().unwrap_or_else(|| panic!("{key}"))),
    }
}

fn number(value: &JsValue, key: &str) -> f64 {
    match field(value, key) {
        JsValue::Number(n) => *n,
        other => panic!("{key}: not a number: {other:?}"),
    }
}

fn items(value: &JsValue) -> &[JsValue] {
    value.as_array().expect("an array")
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A malformed case's bytes: its text, its `hex`, or its `fill`.
fn bytes_of(case: &JsValue) -> Vec<u8> {
    if let Some(text) = field(case, "text").as_str() {
        return text.as_bytes().to_vec();
    }
    if let Some(digits) = field(case, "hex").as_str() {
        return hex(digits);
    }
    let fill = field(case, "fill");
    let (open, close) = (text(fill, "open"), text(fill, "close"));
    let size = number(fill, "bytes") as usize;
    let middle = text(fill, "char").repeat(size - open.len() - close.len());
    format!("{open}{middle}{close}").into_bytes()
}

/// The core's text, `None` while there is no file.
fn text_of(file: &Option<KeysFile>) -> Option<String> {
    file.as_ref().map(|f| f.text().to_string())
}

/// What the core counts: each provider and its key, in order.
fn counted_of(file: &KeysFile) -> Vec<(String, String)> {
    file.counted()
        .into_iter()
        .map(|c| (c.id, c.key.to_string()))
        .collect()
}

/// A long text: its length and its SHA-256, the reference's.
fn sized(file: &KeysFile, reference: &JsValue, case: &str) {
    use sha2::{Digest, Sha256};
    assert_eq!(
        file.text_len(),
        number(reference, "text_length") as usize,
        "{case}"
    );
    let digest: String = Sha256::digest(file.text().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(digest, text(reference, "text_sha256"), "{case}");
}

/// The reference's counted keys (`hasApiKey`, `String(apiKey)`), as
/// [`KeysFile::counted`] must give them, each checked against `holds`.
/// A key whose `String(apiKey)` threw isn't counted: the core counts only
/// what can be made a string (`counted_key`; deviation
/// `rpc-keys-unstringifiable`).
fn check_keys(file: &KeysFile, keys: &JsValue, case: &str) {
    let mut expected = Vec::new();
    for entry in items(keys) {
        let id = text(entry, "id");
        if field(entry, "error").as_str().is_some() {
            assert!(!file.counts(id), "{case}: {id}");
            continue;
        }
        expected.push((id.to_owned(), text(entry, "key").to_owned()));
    }
    assert_eq!(counted_of(file), expected, "{case}");
    for (counted, entry) in file.counted().iter().zip(
        items(keys)
            .iter()
            .filter(|e| field(e, "error").as_str().is_none()),
    ) {
        let bytes = number(entry, "bytes") as usize;
        let holds = field(entry, "string") == &JsValue::Bool(true)
            && field(entry, "well_formed") == &JsValue::Bool(true)
            && (1..=MAX_SECRET_BYTES).contains(&bytes);
        assert_eq!(counted.holds, holds, "{case}: {}", counted.id);
    }
}

/// `{ apiKey, enabled: true, addedAt }`, as the reference writes a set.
fn record(key: &str, at: f64) -> JsValue {
    JsValue::Object(vec![
        (JsString::from("apiKey"), JsValue::string(key)),
        (JsString::from("enabled"), JsValue::Bool(true)),
        (JsString::from("addedAt"), JsValue::Number(at)),
    ])
}

#[test]
fn the_runs_replay_through_the_codec() {
    let section = section();
    let runs = items(field(&section, "runs"));
    assert!(runs.len() >= 10);
    for run in runs {
        let id = text(run, "id");
        let mut file = maybe(run, "start").and_then(|start| {
            let parsed = KeysFile::parse(start.as_bytes());
            match text(run, "start_core") {
                "parsed" => Some(parsed.unwrap_or_else(|| panic!("{id}: the start"))),
                // `rpc-keys-unreadable`: the reference reads `{}` and its
                // next save replaces the file; the core sets it aside, then
                // writes the same text.
                "unreadable" => {
                    assert_eq!(text(run, "row"), "rpc-keys-unreadable", "{id}");
                    assert!(parsed.is_none(), "{id}");
                    None
                }
                other => panic!("{id}: {other}"),
            }
        });
        let mut before = maybe(run, "start").map(str::to_owned);
        let steps = items(field(run, "steps"));
        for (i, step) in steps.iter().enumerate() {
            let case = format!("{id} step {i}");
            let provider = text(step, "id");
            let success = field(field(step, "result"), "success") == &JsValue::Bool(true);
            let after = maybe(step, "text");
            match text(step, "core") {
                // main's registry refuses the id before the core is asked.
                "main_refuses" => assert!(!success, "{case}"),
                "set" => {
                    let key = text(step, "key");
                    assert!(success, "{case}");
                    assert!(entry_name(provider).is_some() && holdable(key), "{case}");
                    let at = number(step, "at");
                    file.get_or_insert_with(KeysFile::default)
                        .set(provider, key, at as u64);
                }
                "remove" => {
                    let removed = file.as_mut().is_some_and(|f| f.delete(provider, true));
                    if removed {
                        assert!(success && field(step, "wrote") == &JsValue::Bool(true));
                    }
                }
                // `rpc-key-provider-id`: the reference takes any id main's
                // registry has; the core refuses a set for one outside the
                // entry form, and the file is left as it was.
                "refused" => {
                    assert_eq!(text(step, "row"), "rpc-key-provider-id", "{case}");
                    assert!(success && entry_name(provider).is_none(), "{case}");
                    assert_ne!(after, before.as_deref(), "{case}: the reference took it");
                    assert_eq!(text_of(&file).as_deref(), before.as_deref(), "{case}");
                    assert_eq!(i + 1, steps.len(), "{case}: a last step");
                    continue;
                }
                // `rpc-key-provider-id`: `keys.__proto__ = record` makes the
                // record the object's prototype, so the reference answers
                // it until the next start but never writes it. The core's
                // record is an own property, which it writes.
                "own_property" => {
                    assert_eq!(text(step, "row"), "rpc-key-provider-id", "{case}");
                    assert!(success && field(step, "has") == &JsValue::Bool(true));
                    assert_eq!(after, before.as_deref(), "{case}: not written");
                    let (key, at) = (text(step, "key"), number(step, "at"));
                    let mut expected = fc_json::parse(before.as_deref().unwrap_or("{}")).unwrap();
                    expected.set(provider, record(key, at));
                    let core = file.get_or_insert_with(KeysFile::default);
                    assert!(entry_name(provider).is_some(), "{case}");
                    core.set(provider, key, at as u64);
                    assert_eq!(*core.text(), expected.stringify_pretty(), "{case}");
                    assert!(core.counts(provider), "{case}");
                    assert_eq!(i + 1, steps.len(), "{case}: a last step");
                    continue;
                }
                other => panic!("{case}: {other}"),
            }
            assert_eq!(text_of(&file).as_deref(), after, "{case}");
            let has = field(step, "has") == &JsValue::Bool(true);
            let empty = KeysFile::default();
            let core = file.as_ref().unwrap_or(&empty);
            assert_eq!(core.counts(provider), has, "{case}");
            check_keys(core, field(step, "keys"), &case);
            before = after.map(str::to_owned);
        }
        // `rpc-keys-bound`: the reference has no bound, and the file the
        // core writes with no key store has none; 16 is the secrets file's
        // (tests/rpc_keys.rs).
        if id == "seventeen" {
            let counted = file.as_ref().map(KeysFile::counted).unwrap_or_default();
            assert!(counted.len() > MAX_KEYS && counted.iter().all(|c| c.holds));
        }
    }
}

#[test]
fn each_malformed_file_reads_as_the_core_documents() {
    let section = section();
    let cases = items(field(&section, "malformed"));
    assert!(cases.len() >= 30);
    for case in cases {
        let id = text(case, "id");
        let bytes = bytes_of(case);
        let read = field(case, "read");
        let set = field(case, "set");
        let fresh = || {
            let mut file = KeysFile::default();
            file.set("alchemy", "k-new", number(set, "at") as u64);
            file.text().to_string()
        };
        match text(case, "core") {
            "unreadable" => {
                // `rpc-keys-unreadable`: what the reference reads as `{}`
                // (not JSON), the value it reads (not an object), or a file
                // over the design's 1 MiB are set aside.
                assert_eq!(text(case, "row"), "rpc-keys-unreadable", "{id}");
                match text(case, "reason") {
                    "not_json" => {
                        assert!(KeysFile::parse(&bytes).is_none(), "{id}");
                        // The reference reads `{}` and its set replaces the
                        // file, as the core's set after the set-aside does.
                        if field(read, "error").as_str().is_some() {
                            assert_eq!(maybe(set, "text"), Some(fresh().as_str()), "{id}");
                        }
                    }
                    "not_object" => {
                        assert!(field(read, "text").as_str().is_some(), "{id}");
                        assert!(KeysFile::parse(&bytes).is_none(), "{id}");
                    }
                    "too_large" => {
                        assert!(bytes.len() > MAX_FILE_BYTES, "{id}");
                        // The reference reads it.
                        assert!(
                            matches!(field(read, "text_length"), JsValue::Number(_)),
                            "{id}"
                        );
                    }
                    other => panic!("{id}: {other}"),
                }
            }
            "parsed" => {
                assert!(bytes.len() <= MAX_FILE_BYTES, "{id}");
                let file = KeysFile::parse(&bytes).unwrap_or_else(|| panic!("{id}"));
                match field(read, "text").as_str() {
                    Some(reference) => assert_eq!(*file.text(), *reference, "{id}"),
                    None => sized(&file, read, id),
                }
                check_keys(&file, field(case, "keys"), id);
                assert!(field(field(set, "result"), "success") == &JsValue::Bool(true));
                let mut file = file;
                file.set("alchemy", "k-new", number(set, "at") as u64);
                match field(set, "text").as_str() {
                    Some(reference) => assert_eq!(*file.text(), *reference, "{id}: the set"),
                    None => sized(&file, set, id),
                }
            }
            other => panic!("{id}: {other}"),
        }
    }
}
