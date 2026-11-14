//! `vectors/secrets.json` (design 0013, PRF-1a), byte for byte: every file
//! in form reads and writes back exactly, names the recorded items, and
//! opens or refuses as recorded; every malformed text is refused with its
//! reason; every change gives exactly the text after it, drawing exactly
//! the recorded nonces, or is refused. fc-profile's tests replay the same
//! vectors through the reader a profile delete uses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;

use fc_keystore::{
    AAD_LABEL, Backend, Binding, Blob, EntryName, ItemId, MAX_BINDING_MEMBERS,
    MAX_BINDING_NAME_BYTES, MAX_BINDING_VALUE_BYTES, MAX_BLOB_BYTES, MAX_ENTRIES, MAX_FILE_BYTES,
    MAX_ITEMS, MAX_NAME_BYTES, MAX_SECRET_BYTES, NONCE_BYTES, NamedItem, Policy, Put, Refused,
    Sealed, SecretsFile, TAG_BYTES, VERSION, WrapKey, associated_data,
};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/secrets.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {value}"))
}

fn binding_of(value: &Value) -> Binding {
    let members = value.as_object().unwrap();
    Binding::new(
        members
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str().unwrap())),
    )
    .unwrap()
}

fn wrap_key(text: &str) -> WrapKey {
    let mut bytes: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
    WrapKey::take(&mut bytes)
}

fn item(text: &str) -> ItemId {
    ItemId::parse(text).unwrap()
}

fn policy(text: &str) -> Policy {
    Policy::parse(text).unwrap()
}

fn backend(text: &str) -> Backend {
    Backend::parse(text).unwrap()
}

fn items_json(items: &[NamedItem]) -> Value {
    Value::Array(
        items
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

fn parse(text: &str) -> SecretsFile {
    SecretsFile::parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e:?}: {text}"))
}

/// A file in form: it reads, writes back exactly, and names exactly the
/// recorded items. fc-profile's tests replay the same files through the
/// reader a profile delete uses.
fn check_in_form(id: &str, text: &str, items: &Value) -> SecretsFile {
    let file = parse(text);
    assert_eq!(file.text(), text, "{id}");
    assert_eq!(items_json(&file.items()), *items, "{id}");
    file
}

#[test]
fn constants() {
    let v = vectors();
    let c = &v["constants"];
    assert_eq!(c["version"], VERSION);
    assert_eq!(c["aad_label"], AAD_LABEL);
    let policies: Vec<&str> = Policy::ALL.iter().map(|p| p.name()).collect();
    assert_eq!(c["policies"], serde_json::json!(policies));
    let backends: Vec<&str> = Backend::ALL.iter().map(|b| b.name()).collect();
    assert_eq!(c["backends"], serde_json::json!(backends));
    for (key, value) in [
        ("max_items", MAX_ITEMS),
        ("max_entries", MAX_ENTRIES),
        ("max_name_bytes", MAX_NAME_BYTES),
        ("max_secret_bytes", MAX_SECRET_BYTES),
        ("max_binding_members", MAX_BINDING_MEMBERS),
        ("max_binding_name_bytes", MAX_BINDING_NAME_BYTES),
        ("max_binding_value_bytes", MAX_BINDING_VALUE_BYTES),
        ("max_blob_bytes", MAX_BLOB_BYTES),
        ("max_file_bytes", MAX_FILE_BYTES),
        ("nonce_bytes", NONCE_BYTES),
        ("tag_bytes", TAG_BYTES),
    ] {
        assert_eq!(c[key], value, "{key}");
    }
}

#[test]
fn files_in_form() {
    let v = vectors();
    let files = v["files"].as_array().unwrap();
    assert!(!files.is_empty());
    for case in files {
        let id = str_of(case, "id");
        let file = check_in_form(id, str_of(case, "text"), &case["items"]);
        let mut names = Vec::new();
        for entry in case["entries"].as_array().unwrap() {
            let name = EntryName::new(str_of(entry, "name")).unwrap();
            let binding = binding_of(&entry["binding"]);
            assert_eq!(binding.canonical(), str_of(entry, "canonical"), "{id}");
            assert_eq!(
                hex::encode(associated_data(&name, &binding)),
                str_of(entry, "aad"),
                "{id}"
            );
            assert_eq!(file.entry_key(&name), Some(policy(str_of(entry, "key"))));
            assert_eq!(file.binding(&name), Some(&binding), "{id}");
            names.push(name);
        }
        assert_eq!(
            file.entry_names().cloned().collect::<Vec<_>>(),
            names,
            "{id}"
        );
        for open in case["opens"].as_array().unwrap() {
            let name = EntryName::new(str_of(open, "name")).unwrap();
            let binding = binding_of(&open["binding"]);
            let result = file.open(&name, &binding, &wrap_key(str_of(open, "key")));
            match (open.get("secret"), open.get("error")) {
                (Some(secret), None) => assert_eq!(
                    result.map(|s| s.expose().to_vec()).ok(),
                    Some(secret.as_str().unwrap().as_bytes().to_vec()),
                    "{id}: {open}"
                ),
                (None, Some(error)) => {
                    assert_eq!(
                        result.err().map(|e| e.code()),
                        error.as_str(),
                        "{id}: {open}"
                    )
                }
                _ => panic!("{id}: {open}"),
            }
        }
    }
}

#[test]
fn malformed_texts() {
    let v = vectors();
    let cases = v["malformed"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let id = str_of(case, "id");
        let bytes = if let Some(text) = case.get("text") {
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
        };
        assert_eq!(
            SecretsFile::parse(&bytes).err().map(|e| e.code()),
            Some(str_of(case, "reason")),
            "{id}"
        );
    }
}

/// An RNG that hands out the recorded draws, then fails.
struct Recorded(VecDeque<Vec<u8>>);

#[derive(Debug)]
struct Exhausted;

impl std::fmt::Display for Exhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no recorded draw left")
    }
}

impl std::error::Error for Exhausted {}

impl rand_core::TryRng for Recorded {
    type Error = Exhausted;

    fn try_next_u32(&mut self) -> Result<u32, Exhausted> {
        Err(Exhausted)
    }

    fn try_next_u64(&mut self) -> Result<u64, Exhausted> {
        Err(Exhausted)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Exhausted> {
        let draw = self.0.pop_front().ok_or(Exhausted)?;
        assert_eq!(draw.len(), dst.len(), "a draw of another length");
        dst.copy_from_slice(&draw);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Recorded {}

fn put_of(value: &Value) -> (EntryName, Binding, Vec<u8>) {
    (
        EntryName::new(str_of(value, "name")).unwrap(),
        binding_of(&value["binding"]),
        str_of(value, "secret").as_bytes().to_vec(),
    )
}

fn sealed_of(value: &Value) -> Sealed {
    let blob = value["blob"]
        .as_str()
        .map(|b| Blob::from_base64(b).unwrap());
    Sealed::new(
        backend(str_of(value, "backend")),
        policy(str_of(value, "policy")),
        item(str_of(value, "item")),
        blob,
    )
    .unwrap()
}

fn apply(file: &SecretsFile, op: &[Value], rng: &mut Recorded) -> Result<SecretsFile, Refused> {
    let s = |i: usize| op[i].as_str().unwrap();
    match s(0) {
        "begin_create" => file.begin_create(policy(s(1)), backend(s(2)), item(s(3))),
        "commit" => {
            let put = (!op[4].is_null()).then(|| put_of(&op[4]));
            let old = op[3].as_str().map(wrap_key);
            file.commit(
                &sealed_of(&op[1]),
                &wrap_key(s(2)),
                old.as_ref(),
                put.as_ref().map(|(name, binding, secret)| Put {
                    name: name.clone(),
                    binding: binding.clone(),
                    secret,
                }),
                rng,
            )
        }
        "put" => {
            let (name, binding, secret) = put_of(&op[3]);
            file.put(
                policy(s(1)),
                &wrap_key(s(2)),
                Put {
                    name,
                    binding,
                    secret: &secret,
                },
                rng,
            )
        }
        "remove" => file.remove(&EntryName::new(s(1)).unwrap()),
        "settle" => Ok(file.settle()),
        "forgotten" => Ok(file.forgotten(item(s(1)))),
        "drop_foreign" => Ok(file.drop_foreign(op[1].as_str().map(backend))),
        other => panic!("op {other}"),
    }
}

#[test]
fn transitions() {
    let v = vectors();
    let cases = v["transitions"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let id = str_of(case, "id");
        let before = parse(str_of(case, "before"));
        assert_eq!(before.text(), str_of(case, "before"), "{id}");
        let draws = case["rng"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| hex::decode(d.as_str().unwrap()).unwrap())
            .collect();
        let mut rng = Recorded(draws);
        let result = apply(&before, case["op"].as_array().unwrap(), &mut rng);
        match (case.get("after"), case.get("refused")) {
            (Some(after), None) => {
                let next = result.unwrap_or_else(|e| panic!("{id}: {e:?}"));
                assert_eq!(next.text(), after.as_str().unwrap(), "{id}");
                assert!(rng.0.is_empty(), "{id}: draws left");
                check_in_form(id, after.as_str().unwrap(), &case["after_items"]);
            }
            (None, Some(refused)) => {
                assert_eq!(result.err().map(|e| e.code()), refused.as_str(), "{id}");
            }
            _ => panic!("{id}"),
        }
    }
}
