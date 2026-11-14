//! `vectors/secrets.json` (design 0013, PRF-1a) through the reader a profile
//! delete uses (PRF-3): every file in form, and every transition's text
//! before and after, names exactly the items fc-keystore names, in its
//! order; every malformed text, in either layout, names nothing known
//! (`forget_unknown`), never a partial or empty list; a missing file names
//! nothing; and a forget-file record of a profile still listed, whose own
//! secrets file can't be read, forgets none of its items.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fc_json::JsValue;
use fc_keystore::SecretsFile;
use fc_profile::forget::{
    self, Backend, ForgetFile, Item, Malformed, Policy, Record, secrets_items, secrets_named,
};
use fc_profile::{Store, StoreError, Style};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../vectors/secrets.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn items_json(items: &[Item]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "backend": item.backend.name(),
                    "policy": item.policy.name(),
                    "item": item.item,
                })
            })
            .collect(),
    )
}

/// What fc-keystore names in a file in form.
fn keystore_items(text: &str) -> Value {
    let file = SecretsFile::parse(text.as_bytes()).unwrap();
    Value::Array(
        file.items()
            .iter()
            .map(|named| {
                serde_json::json!({
                    "backend": named.backend.name(),
                    "policy": named.policy.name(),
                    "item": named.item.hex(),
                })
            })
            .collect(),
    )
}

/// A malformed case's bytes.
fn malformed_bytes(case: &Value) -> Vec<u8> {
    if let Some(text) = case.get("text") {
        text.as_str().unwrap().as_bytes().to_vec()
    } else if let Some(hex) = case.get("text_hex") {
        hex::decode(hex.as_str().unwrap()).unwrap()
    } else {
        let repeat = case["text_repeat"].as_array().unwrap();
        repeat[0]
            .as_str()
            .unwrap()
            .repeat(repeat[1].as_u64().unwrap() as usize)
            .into_bytes()
    }
}

/// Files by path, read as freedom-cored's store reads them: each invalid
/// UTF-8 sequence as U+FFFD.
#[derive(Default)]
struct Memory {
    files: BTreeMap<String, Vec<u8>>,
}

impl Store for Memory {
    fn read(&mut self, path: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .files
            .get(path)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned()))
    }

    fn is_dir(&mut self, path: &str) -> Result<bool, StoreError> {
        let prefix = format!("{path}/");
        Ok(self.files.keys().any(|file| file.starts_with(&prefix)))
    }

    fn list_dirs(&mut self, _path: &str) -> Result<Vec<String>, StoreError> {
        Ok(Vec::new())
    }

    fn ensure_dir(&mut self, _path: &str) -> Result<(), StoreError> {
        Ok(())
    }

    fn write(&mut self, path: &str, text: &str) -> Result<(), StoreError> {
        self.files.insert(path.to_owned(), text.as_bytes().to_vec());
        Ok(())
    }

    fn resolve(&self, path: &str) -> String {
        Style::Posix.normalize(path)
    }
}

const ROOT: &str = "/app/Profiles/work";

fn layouts() -> [String; 2] {
    forget::secrets_paths(ROOT, Style::Posix)
}

#[test]
fn files_in_form_name_what_fc_keystore_names() {
    let v = vectors();
    let mut checked = 0;
    for case in v["files"].as_array().unwrap() {
        let id = str_of(case, "id");
        let text = str_of(case, "text");
        let items = secrets_items(text).unwrap_or_else(|_| panic!("{id}"));
        assert_eq!(items_json(&items), case["items"], "{id}");
        checked += 1;
    }
    for case in v["transitions"].as_array().unwrap() {
        let id = str_of(case, "id");
        let before = str_of(case, "before");
        assert_eq!(
            items_json(&secrets_items(before).unwrap()),
            keystore_items(before),
            "{id}: before"
        );
        if let Some(after) = case.get("after") {
            let after = after.as_str().unwrap();
            let items = items_json(&secrets_items(after).unwrap());
            assert_eq!(items, case["after_items"], "{id}: after");
            assert_eq!(items, keystore_items(after), "{id}: after");
        }
        checked += 1;
    }
    assert_eq!(checked, 15 + 48);
}

#[test]
fn every_malformed_text_names_nothing_known() {
    let v = vectors();
    let cases = v["malformed"].as_array().unwrap();
    assert_eq!(cases.len(), 77);
    // A file in form, for the other layout.
    let good = str_of(&v["files"][1], "text").as_bytes().to_vec();
    assert!(
        !secrets_items(str_of(&v["files"][1], "text"))
            .unwrap()
            .is_empty()
    );
    for case in cases {
        let id = str_of(case, "id");
        let bytes = malformed_bytes(case);
        if let Ok(text) = std::str::from_utf8(&bytes) {
            assert_eq!(secrets_items(text), Err(Malformed), "{id}");
        }
        for (index, path) in layouts().iter().enumerate() {
            // Alone in either layout, and beside a file in form in the
            // other: what the profile names is unknown, so nothing of
            // the good file is recorded either.
            for with_good in [false, true] {
                let mut store = Memory::default();
                store.files.insert(path.clone(), bytes.clone());
                if with_good {
                    store
                        .files
                        .insert(layouts()[1 - index].clone(), good.clone());
                }
                assert_eq!(
                    secrets_named(&mut store, ROOT, Style::Posix),
                    Err(Malformed),
                    "{id} at {path}, beside a good file: {with_good}"
                );
            }
        }
    }
}

#[test]
fn a_missing_file_names_nothing() {
    let mut store = Memory::default();
    assert_eq!(
        secrets_named(&mut store, ROOT, Style::Posix),
        Ok(Vec::new())
    );
    // A file in form in either layout names its items, each once.
    let v = vectors();
    let text = str_of(&v["files"][1], "text");
    for path in layouts() {
        let mut store = Memory::default();
        store.files.insert(path.clone(), text.as_bytes().to_vec());
        let named = secrets_named(&mut store, ROOT, Style::Posix).unwrap();
        assert_eq!(items_json(&named), v["files"][1]["items"], "{path}");
    }
    let mut store = Memory::default();
    for path in layouts() {
        store.files.insert(path, text.as_bytes().to_vec());
    }
    let named = secrets_named(&mut store, ROOT, Style::Posix).unwrap();
    assert_eq!(items_json(&named), v["files"][1]["items"]);
}

fn catalog() -> JsValue {
    fc_json::parse(&format!(
        r#"{{"version":1,"profiles":[{{"id":"work","dir":"{ROOT}","slot":1}}]}}"#
    ))
    .unwrap()
}

fn record_of(items: &[&str]) -> ForgetFile {
    ForgetFile {
        deleted: vec![Record {
            id: "work".into(),
            dir: ROOT.into(),
            items: items
                .iter()
                .map(|item| Item {
                    backend: Backend::MacosKeychain,
                    policy: Policy::Unattended,
                    item: (*item).to_owned(),
                })
                .collect(),
        }],
    }
}

#[test]
fn a_listed_profile_whose_file_cant_be_read_forgets_none_of_its_items() {
    let v = vectors();
    let named = "a1".repeat(16);
    let other = "f0".repeat(16);
    // The profile's own file in form, naming `named` (the `enrolled` file):
    // that item is dropped from the record without a forget, the other kept.
    let enrolled = str_of(&v["files"][1], "text");
    assert!(enrolled.contains(&named));
    let mut store = Memory::default();
    store
        .files
        .insert(layouts()[0].clone(), enrolled.as_bytes().to_vec());
    let mut file = record_of(&[&named, &other]);
    assert!(file.drop_still_named(&mut store, &catalog(), Style::Posix));
    assert_eq!(file.deleted[0].items.len(), 1);
    assert_eq!(file.deleted[0].items[0].item, other);
    // Malformed: it may name any of them, so none is forgotten.
    for case in v["malformed"].as_array().unwrap() {
        let mut store = Memory::default();
        store
            .files
            .insert(layouts()[0].clone(), malformed_bytes(case));
        let mut file = record_of(&[&named, &other]);
        assert!(
            file.drop_still_named(&mut store, &catalog(), Style::Posix),
            "{}",
            str_of(case, "id")
        );
        assert!(file.live().is_empty(), "{}", str_of(case, "id"));
    }
    // A profile no longer listed: its record's items are all forgotten.
    let mut store = Memory::default();
    store
        .files
        .insert(layouts()[0].clone(), b"{not json".to_vec());
    let mut file = record_of(&[&named, &other]);
    let empty = fc_json::parse(r#"{"version":1,"profiles":[]}"#).unwrap();
    assert!(!file.drop_still_named(&mut store, &empty, Style::Posix));
    assert_eq!(file.live().len(), 2);
}
