//! Replays vectors/approvals.json's `stores`, which the pinned reference's
//! four grant stores produced (design 0012, APR-2): each operation's result
//! and the file's text after it, byte for byte, and what each store reads
//! from a malformed file.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_approval::stores::{
    CapStore, DappStore, Effect, RadicleFlag, RadicleStore, StoreKind, SwarmFlag, SwarmStore,
    Unreadable, js_text,
};
use serde_json::{Map, Value, json};

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/approvals.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn stores() -> Value {
    load()["stores"].clone()
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    let digits = text.strip_prefix("0x").unwrap();
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}

fn str_arg(args: &Value, index: usize) -> &str {
    args[index].as_str().unwrap()
}

fn u32_arg(args: &Value, index: usize) -> u32 {
    u32::try_from(args[index].as_u64().unwrap()).unwrap()
}

fn at(step: &Value) -> u64 {
    step["at"].as_u64().unwrap()
}

/// What a step's operation answered in the core.
enum Answer {
    Value(Value),
    /// The operation wrote (or not) as its effect says.
    Applied(Value, Effect),
}

fn records(values: Vec<&Value>) -> Value {
    Value::Array(values.into_iter().cloned().collect())
}

trait Store: Sized {
    const KIND: StoreKind;
    fn new() -> Self;
    fn load(bytes: &[u8], at_ms: u64) -> Result<Self, Unreadable>;
    fn text(&self) -> String;
    fn apply(&mut self, op: &str, args: &Value, at_ms: u64) -> Answer;
}

impl Store for DappStore {
    const KIND: StoreKind = StoreKind::Dapp;
    fn new() -> Self {
        DappStore::new()
    }
    fn load(bytes: &[u8], _: u64) -> Result<Self, Unreadable> {
        DappStore::load(bytes)
    }
    fn text(&self) -> String {
        DappStore::text(self).unwrap()
    }
    fn apply(&mut self, op: &str, args: &Value, now: u64) -> Answer {
        let applied = |value: Value, effect| Answer::Applied(value, effect);
        match op {
            "grantPermission" => {
                let out = self.connect(
                    str_arg(args, 0),
                    u32_arg(args, 1),
                    args[2].as_u64().unwrap(),
                    now,
                );
                applied(out.value, out.effect)
            }
            "revokePermission" => {
                let out = self.revoke(str_arg(args, 0));
                applied(json!(out.value), out.effect)
            }
            "revokePermissionsForWalletIndex" => {
                let out = self.forget_account(u32_arg(args, 0));
                applied(json!(out.value), out.effect)
            }
            "updateLastUsed" => {
                let chain = args.get(1).and_then(Value::as_u64);
                let out = self.touch(str_arg(args, 0), chain, now);
                applied(json!(out.value), out.effect)
            }
            "updateWalletIndex" => {
                let out = self.set_account(str_arg(args, 0), u32_arg(args, 1), now);
                applied(json!(out.value), out.effect)
            }
            "setSigningAutoApprove" => {
                assert_eq!(
                    args[1],
                    json!(false),
                    "the core only turns today's flag off"
                );
                let out = self.signing_off(str_arg(args, 0));
                applied(json!(out.value), out.effect)
            }
            "removeTransactionAutoApprove" => {
                let selector = &str_arg(args, 2)[..10];
                let out = self.remove_transaction_rule(
                    str_arg(args, 0),
                    &hex(str_arg(args, 1)),
                    &hex(selector),
                    args[3].as_u64().unwrap(),
                );
                applied(json!(out.value), out.effect)
            }
            "getPermission" => {
                Answer::Value(self.entry(str_arg(args, 0)).cloned().unwrap_or(Value::Null))
            }
            "getAllPermissions" => Answer::Value(records(self.records())),
            other => panic!("dapp: no core operation for {other}"),
        }
    }
}

impl Store for SwarmStore {
    const KIND: StoreKind = StoreKind::Swarm;
    fn new() -> Self {
        SwarmStore::new()
    }
    fn load(bytes: &[u8], _: u64) -> Result<Self, Unreadable> {
        SwarmStore::load(bytes)
    }
    fn text(&self) -> String {
        SwarmStore::text(self).unwrap()
    }
    fn apply(&mut self, op: &str, args: &Value, now: u64) -> Answer {
        if op == "getAllPermissions" {
            return Answer::Value(records(self.records()));
        }
        let key = str_arg(args, 0);
        let flag = || {
            args.get(1)
                .and_then(Value::as_str)
                .and_then(SwarmFlag::from_name)
        };
        match op {
            "grantPermission" => {
                let out = self.connect(key, now);
                Answer::Applied(out.value, out.effect)
            }
            "revokePermission" => {
                let out = self.revoke(key);
                Answer::Applied(json!(out.value), out.effect)
            }
            "updateLastUsed" => {
                let out = self.touch(key, now);
                Answer::Applied(json!(out.value), out.effect)
            }
            "setAutoApprove" => match flag() {
                // Another name: refused, and nothing written.
                None => Answer::Applied(json!(false), Effect::Unchanged),
                Some(flag) => {
                    let out = self.set_flag(key, flag, args[2].as_bool().unwrap());
                    Answer::Applied(json!(out.value), out.effect)
                }
            },
            "getAutoApprove" => {
                Answer::Value(json!(flag().is_some_and(|flag| self.flag(key, flag))))
            }
            "grantMessaging" => {
                let out = self.grant_messaging(key, now);
                Answer::Applied(json!(out.value), out.effect)
            }
            "revokeMessaging" => {
                let out = self.revoke_messaging(key);
                Answer::Applied(json!(out.value), out.effect)
            }
            "hasMessagingGrant" => Answer::Value(json!(self.has_messaging(key))),
            other => panic!("swarm: no core operation for {other}"),
        }
    }
}

impl Store for RadicleStore {
    const KIND: StoreKind = StoreKind::Radicle;
    fn new() -> Self {
        RadicleStore::new()
    }
    fn load(bytes: &[u8], _: u64) -> Result<Self, Unreadable> {
        RadicleStore::load(bytes)
    }
    fn text(&self) -> String {
        RadicleStore::text(self).unwrap()
    }
    fn apply(&mut self, op: &str, args: &Value, now: u64) -> Answer {
        if op == "getAllPermissions" {
            return Answer::Value(records(self.records()));
        }
        let key = str_arg(args, 0);
        let flag = || {
            args.get(1)
                .and_then(Value::as_str)
                .and_then(RadicleFlag::from_name)
        };
        match op {
            "grantPermission" => {
                let out = self.connect(key, now);
                Answer::Applied(out.value, out.effect)
            }
            "revokePermission" => {
                let out = self.revoke(key);
                Answer::Applied(json!(out.value), out.effect)
            }
            "updateLastUsed" => {
                let out = self.touch(key, now);
                Answer::Applied(json!(out.value), out.effect)
            }
            "grantSigning" => {
                let out = self.grant_signing(key);
                Answer::Applied(json!(out.value), out.effect)
            }
            "hasSigningGrant" => Answer::Value(json!(self.has_signing(key))),
            "setAutoApprove" => match flag() {
                None => Answer::Applied(json!(false), Effect::Unchanged),
                Some(flag) => {
                    let out = self.set_flag(key, flag, args[2].as_bool().unwrap());
                    Answer::Applied(json!(out.value), out.effect)
                }
            },
            "getAutoApprove" => {
                Answer::Value(json!(flag().is_some_and(|flag| self.flag(key, flag))))
            }
            other => panic!("radicle: no core operation for {other}"),
        }
    }
}

/// x402's caps, as `getAllPermissions` lists them: `{ origin, chainId,
/// asset, ...record }`, from the `"<chainId>:<asset>"` key.
fn cap_list(store: &CapStore) -> Value {
    Value::Array(
        store
            .caps()
            .map(|(origin, key, record)| {
                let mut parts = key.split(':');
                let chain: f64 = parts.next().unwrap().parse().unwrap();
                let mut out = Map::new();
                out.insert("origin".into(), json!(origin));
                out.insert("chainId".into(), json!(chain as u64));
                out.insert("asset".into(), json!(parts.next().unwrap_or("")));
                for (field, value) in record.as_object().unwrap() {
                    out.insert(field.clone(), value.clone());
                }
                Value::Object(out)
            })
            .collect(),
    )
}

/// A run of a site store: each step done by the core, or read from the
/// reference's text where the core doesn't do it (`core: load`).
fn replay<S: Store>(run: &Value) {
    let id = format!("{}/{}", S::KIND.name(), run["id"].as_str().unwrap());
    let mut store = match run["start"].as_str() {
        Some(text) => S::load(text.as_bytes(), 0).unwrap_or_else(|e| panic!("{id}: {e}")),
        None => S::new(),
    };
    // Whether the store's text is the file's yet: from the first write.
    let mut synced = false;
    for (index, step) in run["steps"].as_array().unwrap().iter().enumerate() {
        let op = step["op"].as_str().unwrap();
        let label = format!("{id} step {index} ({op})");
        let file = step["text"].as_str();
        match step["core"].as_str() {
            Some("load") => {
                // An older build's write: read as it is, written back as it is.
                let text = file.unwrap();
                store =
                    S::load(text.as_bytes(), at(step)).unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(store.text(), text, "{label}");
                synced = true;
                continue;
            }
            Some("legacy") => {
                assert_eq!(step["wrote"], json!(false), "{label}");
                continue;
            }
            Some(other) => panic!("{label}: core {other}"),
            None => {}
        }
        assert!(step.get("error").is_none(), "{label}: the reference failed");
        match store.apply(op, &step["args"], at(step)) {
            Answer::Value(value) => {
                assert_eq!(js_text(&value), js_text(&step["result"]), "{label}");
                assert_eq!(step["wrote"], json!(false), "{label}");
            }
            Answer::Applied(value, effect) => {
                assert_eq!(js_text(&value), js_text(&step["result"]), "{label}");
                let wrote = effect != Effect::Unchanged;
                assert_eq!(json!(wrote), step["wrote"], "{label}: {effect:?}");
                synced |= wrote;
            }
        }
        if synced {
            assert_eq!(Some(store.text().as_str()), file, "{label}");
        }
    }
}

#[test]
fn site_store_runs() {
    let stores = stores();
    let mut count = 0;
    for (name, replayer) in [
        ("dapp", replay::<DappStore> as fn(&Value)),
        ("swarm", replay::<SwarmStore>),
        ("radicle", replay::<RadicleStore>),
    ] {
        let store = &stores[name];
        assert_eq!(
            store["file"],
            json!(StoreKind::from_name(name).unwrap().file_name())
        );
        for run in store["runs"].as_array().unwrap() {
            replayer(run);
            count += 1;
        }
    }
    assert!(count >= 9);
}

#[test]
fn cap_store_codec() {
    let store = &stores()["x402"];
    assert_eq!(store["file"], json!(StoreKind::X402.file_name()));
    for run in store["runs"].as_array().unwrap() {
        let id = run["id"].as_str().unwrap();
        let mut file = run["start"].as_str().map(str::to_owned);
        for (index, step) in run["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("x402/{id} step {index}");
            let now_s = at(step) / 1000;
            if step["wrote"] == json!(true) {
                // The reference's text, read and written back byte for byte.
                assert_eq!(step["core"], json!("load"), "{label}");
                let text = step["text"].as_str().unwrap();
                assert_eq!(
                    CapStore::load(text.as_bytes(), now_s)
                        .unwrap()
                        .text()
                        .unwrap(),
                    text,
                    "{label}"
                );
                file = Some(text.to_owned());
            }
            if step["op"] == json!("getAllPermissions") {
                // The caps live at that time, as the file gives them.
                let current = CapStore::load(file.as_deref().unwrap().as_bytes(), now_s).unwrap();
                assert_eq!(
                    js_text(&cap_list(&current)),
                    js_text(&step["result"]),
                    "{label}"
                );
            }
        }
    }
}

/// The core's store after reading `text`, or why it is unreadable.
fn read(kind: StoreKind, text: &str) -> Result<Value, Unreadable> {
    let bytes = text.as_bytes();
    let now_s = 1_762_000_000;
    Ok(match kind {
        StoreKind::Dapp => records(DappStore::load(bytes)?.records()),
        StoreKind::Swarm => records(SwarmStore::load(bytes)?.records()),
        StoreKind::Radicle => records(RadicleStore::load(bytes)?.records()),
        StoreKind::X402 => cap_list(&CapStore::load(bytes, now_s)?),
    })
}

/// A connect of `https://other.example` at the vectors' clock, on what the
/// core read from `text` (an empty store for an unreadable file).
fn connect_after(kind: StoreKind, text: &str) -> String {
    const OTHER: &str = "https://other.example";
    const T: u64 = 1_762_000_000_000;
    let bytes = text.as_bytes();
    match kind {
        StoreKind::Dapp => {
            let mut store = DappStore::load(bytes).unwrap_or_default();
            store.connect(OTHER, 0, 1, T);
            store.text().unwrap()
        }
        StoreKind::Swarm => {
            let mut store = SwarmStore::load(bytes).unwrap_or_default();
            store.connect(OTHER, T);
            store.text().unwrap()
        }
        StoreKind::Radicle => {
            let mut store = RadicleStore::load(bytes).unwrap_or_default();
            store.connect(OTHER, T);
            store.text().unwrap()
        }
        StoreKind::X402 => unreachable!("x402's caps are X402-1's"),
    }
}

#[test]
fn malformed_files() {
    let stores = stores();
    for kind in StoreKind::ALL {
        let cases = stores[kind.name()]["malformed"].as_array().unwrap();
        let empty = cases
            .iter()
            .find(|c| c["id"] == json!("empty-object"))
            .unwrap();
        for case in cases {
            let label = format!("{}/{}", kind.name(), case["id"].as_str().unwrap());
            let text = case["text"].as_str().unwrap();
            match case["core"].as_str().unwrap() {
                "unreadable" => {
                    assert!(read(kind, text).is_err(), "{label}");
                    if kind != StoreKind::X402 {
                        // Renamed aside, the store starts empty: a connect
                        // then writes what it writes on an empty file.
                        assert_eq!(
                            connect_after(kind, text),
                            empty["afterGrant"]["text"].as_str().unwrap(),
                            "{label}"
                        );
                    }
                }
                "parsed" => {
                    assert_eq!(
                        js_text(&read(kind, text).unwrap()),
                        js_text(&case["loaded"]["value"]),
                        "{label}"
                    );
                    if kind != StoreKind::X402 {
                        assert_eq!(
                            connect_after(kind, text),
                            case["afterGrant"]["text"].as_str().unwrap(),
                            "{label}"
                        );
                    }
                }
                other => panic!("{label}: core {other}"),
            }
        }
        // Where the reference reads a malformed file as empty, as most of
        // them, its next write is the core's after the rename (the
        // reference's file is lost; the core's is kept aside).
        let as_empty = cases
            .iter()
            .filter(|c| c["core"] == json!("unreadable") && c["afterGrant"] == empty["afterGrant"])
            .count();
        assert!(as_empty >= 5, "{}", kind.name());
    }
}
