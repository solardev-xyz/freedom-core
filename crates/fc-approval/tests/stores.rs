//! Replays vectors/approvals.json's `stores`, which the pinned reference's
//! four grant stores produced (design 0012, APR-2): each operation's result
//! and the file's text after it, byte for byte, what each store reads from
//! a malformed file, and getAllPermissions' order over generated files.
//!
//! The vectors are read as JSON.parse reads them (fc-json), so a recorded
//! double is the reference's own.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_approval::stores::{
    CapStore, Charge, DappStore, Effect, JsValue, RadicleFlag, RadicleStore, StoreKind, SwarmFlag,
    SwarmStore, Unreadable, js_text,
};
use fc_approval::x402::asset_key;

static UNDEFINED: JsValue = JsValue::Undefined;

/// Reading the vectors: a missing field is `undefined`.
trait Read {
    fn at(&self, key: &str) -> &JsValue;
    fn index(&self, index: usize) -> &JsValue;
    fn text(&self) -> &str;
    fn items(&self) -> &[JsValue];
    fn integer(&self) -> u64;
    fn is(&self, text: &str) -> bool;
}

impl Read for JsValue {
    fn at(&self, key: &str) -> &JsValue {
        self.get(key).unwrap_or(&UNDEFINED)
    }
    fn index(&self, index: usize) -> &JsValue {
        self.as_array()
            .and_then(|items| items.get(index))
            .unwrap_or(&UNDEFINED)
    }
    fn text(&self) -> &str {
        self.as_str()
            .unwrap_or_else(|| panic!("not a string: {self:?}"))
    }
    fn items(&self) -> &[JsValue] {
        self.as_array()
            .unwrap_or_else(|| panic!("not an array: {self:?}"))
    }
    fn integer(&self) -> u64 {
        match self {
            JsValue::Number(n) if n.fract() == 0.0 && *n >= 0.0 => *n as u64,
            other => panic!("not an integer: {other:?}"),
        }
    }
    fn is(&self, text: &str) -> bool {
        self.as_str() == Some(text)
    }
}

fn load() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/approvals.json");
    fc_json::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn stores() -> JsValue {
    load().at("stores").clone()
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    let digits = text.strip_prefix("0x").unwrap();
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}

fn bytes_of_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn str_arg(args: &JsValue, index: usize) -> &str {
    args.index(index).text()
}

fn u32_arg(args: &JsValue, index: usize) -> u32 {
    u32::try_from(args.index(index).integer()).unwrap()
}

fn at(step: &JsValue) -> u64 {
    step.at("at").integer()
}

fn boolean(value: bool) -> JsValue {
    JsValue::Bool(value)
}

/// What a step's operation answered in the core.
enum Answer {
    Value(JsValue),
    /// The operation wrote (or not) as its effect says.
    Applied(JsValue, Effect),
    /// The reference's throw: nothing written.
    Throws,
}

fn records(values: Result<Vec<&JsValue>, fc_approval::stores::ToPrimitiveError>) -> Answer {
    match values {
        Ok(values) => Answer::Value(JsValue::Array(values.into_iter().cloned().collect())),
        Err(_) => Answer::Throws,
    }
}

trait Store: Sized {
    const KIND: StoreKind;
    fn new() -> Self;
    fn load(bytes: &[u8], at_ms: u64) -> Result<Self, Unreadable>;
    fn text(&self) -> String;
    fn apply(&mut self, op: &str, args: &JsValue, at_ms: u64) -> Answer;
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
    fn apply(&mut self, op: &str, args: &JsValue, now: u64) -> Answer {
        let applied = |value: bool, effect| Answer::Applied(boolean(value), effect);
        match op {
            "grantPermission" => {
                let out = self.connect(
                    str_arg(args, 0),
                    u32_arg(args, 1),
                    args.index(2).integer(),
                    now,
                );
                Answer::Applied(out.value, out.effect)
            }
            "revokePermission" => {
                let out = self.revoke(str_arg(args, 0));
                applied(out.value, out.effect)
            }
            "revokePermissionsForWalletIndex" => {
                let out = self.forget_account(u32_arg(args, 0));
                let keys = out.value.iter().map(|key| JsValue::string(key.as_str()));
                Answer::Applied(JsValue::Array(keys.collect()), out.effect)
            }
            "updateLastUsed" => {
                let chain = match args.index(1) {
                    JsValue::Undefined => None,
                    chain => Some(chain.integer()),
                };
                let out = self.touch(str_arg(args, 0), chain, now);
                applied(out.value, out.effect)
            }
            "updateWalletIndex" => {
                let out = self.set_account(str_arg(args, 0), u32_arg(args, 1), now);
                applied(out.value, out.effect)
            }
            "setSigningAutoApprove" => {
                assert_eq!(
                    args.index(1),
                    &boolean(false),
                    "the core only turns today's flag off"
                );
                let out = self.signing_off(str_arg(args, 0));
                applied(out.value, out.effect)
            }
            "removeTransactionAutoApprove" => {
                let selector = &str_arg(args, 2)[..10];
                let out = self.remove_transaction_rule(
                    str_arg(args, 0),
                    &hex(str_arg(args, 1)),
                    &hex(selector),
                    args.index(3).integer(),
                );
                applied(out.value, out.effect)
            }
            "getPermission" => Answer::Value(
                self.entry(str_arg(args, 0))
                    .cloned()
                    .unwrap_or(JsValue::Null),
            ),
            "getAllPermissions" => records(self.records()),
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
    fn apply(&mut self, op: &str, args: &JsValue, now: u64) -> Answer {
        if op == "getAllPermissions" {
            return records(self.records());
        }
        let applied = |value: bool, effect| Answer::Applied(boolean(value), effect);
        let key = str_arg(args, 0);
        let flag = || args.index(1).as_str().and_then(SwarmFlag::from_name);
        match op {
            "grantPermission" => {
                let out = self.connect(key, now);
                Answer::Applied(out.value, out.effect)
            }
            "revokePermission" => {
                let out = self.revoke(key);
                applied(out.value, out.effect)
            }
            "updateLastUsed" => {
                let out = self.touch(key, now);
                applied(out.value, out.effect)
            }
            "setAutoApprove" => match flag() {
                // Another name: refused, and nothing written.
                None => applied(false, Effect::Unchanged),
                Some(flag) => {
                    let enabled = args.index(2) == &boolean(true);
                    let out = self.set_flag(key, flag, enabled);
                    applied(out.value, out.effect)
                }
            },
            "getAutoApprove" => {
                Answer::Value(boolean(flag().is_some_and(|flag| self.flag(key, flag))))
            }
            "grantMessaging" => {
                let out = self.grant_messaging(key, now);
                applied(out.value, out.effect)
            }
            "revokeMessaging" => {
                let out = self.revoke_messaging(key);
                applied(out.value, out.effect)
            }
            "hasMessagingGrant" => Answer::Value(boolean(self.has_messaging(key))),
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
    fn apply(&mut self, op: &str, args: &JsValue, now: u64) -> Answer {
        if op == "getAllPermissions" {
            return records(self.records());
        }
        let applied = |value: bool, effect| Answer::Applied(boolean(value), effect);
        let key = str_arg(args, 0);
        let flag = || args.index(1).as_str().and_then(RadicleFlag::from_name);
        match op {
            "grantPermission" => {
                let out = self.connect(key, now);
                Answer::Applied(out.value, out.effect)
            }
            "revokePermission" => {
                let out = self.revoke(key);
                applied(out.value, out.effect)
            }
            "updateLastUsed" => match self.touch(key, now) {
                Ok(out) => applied(out.value, out.effect),
                Err(_) => Answer::Throws,
            },
            "grantSigning" => {
                let out = self.grant_signing(key);
                applied(out.value, out.effect)
            }
            "hasSigningGrant" => Answer::Value(boolean(self.has_signing(key))),
            "setAutoApprove" => match flag() {
                None => applied(false, Effect::Unchanged),
                Some(flag) => {
                    let enabled = args.index(2) == &boolean(true);
                    let out = self.set_flag(key, flag, enabled);
                    applied(out.value, out.effect)
                }
            },
            "getAutoApprove" => {
                Answer::Value(boolean(flag().is_some_and(|flag| self.flag(key, flag))))
            }
            other => panic!("radicle: no core operation for {other}"),
        }
    }
}

/// x402's caps, as `getAllPermissions` lists them: `{ origin, chainId,
/// asset, ...record }`, from the `"<chainId>:<asset>"` key (no `asset`
/// where the key has no colon: `undefined`, which JSON leaves out).
fn cap_list(store: &CapStore) -> JsValue {
    JsValue::Array(
        store
            .caps()
            .map(|(origin, key, record)| {
                let mut parts = key.split(':');
                let chain: f64 = parts.next().unwrap().parse().unwrap();
                let mut out = JsValue::Object(Vec::new());
                out.set("origin", JsValue::string(origin));
                out.set("chainId", JsValue::Number(chain));
                if let Some(asset) = parts.next() {
                    out.set("asset", JsValue::string(asset));
                }
                if let JsValue::Object(fields) = record {
                    for (field, value) in fields {
                        out.set(field.clone(), value.clone());
                    }
                }
                out
            })
            .collect(),
    )
}

/// A run of a site store: each step done by the core, or read from the
/// reference's text where the core doesn't do it (`core: load`).
fn replay<S: Store>(run: &JsValue) {
    let id = format!("{}/{}", S::KIND.name(), run.at("id").text());
    let mut store = match run.at("start").as_str() {
        Some(text) => S::load(text.as_bytes(), 0).unwrap_or_else(|e| panic!("{id}: {e}")),
        None => S::new(),
    };
    // Whether the store's text is the file's yet: from the first write.
    let mut synced = false;
    for (index, step) in run.at("steps").items().iter().enumerate() {
        let op = step.at("op").text();
        let label = format!("{id} step {index} ({op})");
        let file = step.at("text").as_str();
        let wrote = step.at("wrote") == &boolean(true);
        match step.at("core").as_str() {
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
                assert!(!wrote, "{label}");
                continue;
            }
            Some(other) => panic!("{label}: core {other}"),
            None => {}
        }
        if op == "reload" {
            // A new process: the file read again.
            if let Some(text) = file {
                store = S::load(text.as_bytes(), at(step)).unwrap();
            }
            continue;
        }
        let throws = !matches!(step.at("error"), JsValue::Undefined);
        match store.apply(op, step.at("args"), at(step)) {
            Answer::Value(value) => {
                assert!(!throws, "{label}: the reference throws");
                assert_eq!(js_text(&value), js_text(step.at("result")), "{label}");
                assert!(!wrote, "{label}");
            }
            Answer::Applied(value, effect) => {
                assert!(!throws, "{label}: the reference throws");
                assert_eq!(js_text(&value), js_text(step.at("result")), "{label}");
                assert_eq!(effect != Effect::Unchanged, wrote, "{label}: {effect:?}");
                synced |= wrote;
            }
            Answer::Throws => {
                assert!(throws, "{label}: the core throws");
                assert!(!wrote, "{label}");
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
        ("dapp", replay::<DappStore> as fn(&JsValue)),
        ("swarm", replay::<SwarmStore>),
        ("radicle", replay::<RadicleStore>),
    ] {
        let store = stores.at(name);
        assert!(
            store
                .at("file")
                .is(StoreKind::from_name(name).unwrap().file_name())
        );
        for run in store.at("runs").items() {
            replayer(run);
            count += 1;
        }
    }
    assert!(count >= 13);
}

/// A cap's record as a result gives it: `{ origin, chainId, asset,
/// ...record }` without the first three.
fn record_of(result: &JsValue) -> String {
    let JsValue::Object(props) = result else {
        panic!("not a record: {result:?}");
    };
    let fields = props
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "origin" | "chainId" | "asset"))
        .cloned()
        .collect();
    js_text(&JsValue::Object(fields))
}

fn number(value: &JsValue) -> f64 {
    match value {
        JsValue::Number(n) => *n,
        other => panic!("not a number: {other:?}"),
    }
}

/// x402's runs (X402-1): the core makes each operation itself, and its
/// answer and the text after it are the vector's `core`: the reference's
/// with the asset in lowercase (`x402-asset-case`) and a clock set back
/// answering nothing (`x402-clock-back`).
#[test]
fn cap_store_operations() {
    let vectors = stores().at("x402").clone();
    assert!(vectors.at("file").is(StoreKind::X402.file_name()));
    let mut deviations = std::collections::BTreeSet::new();
    for run in vectors.at("runs").items() {
        let id = run.at("id").text();
        let mut store: Option<CapStore> = None;
        let mut last_charge: Option<Charge> = None;
        for (index, step) in run.at("steps").items().iter().enumerate() {
            let label = format!("x402/{id} step {index}");
            let now_s = at(step) / 1000;
            let core = step.at("core");
            if let Some(row) = step.at("deviation").as_str() {
                deviations.insert(row.to_owned());
            }
            // Read at the first operation, as the reference's lazy load.
            let s = store.get_or_insert_with(|| match run.at("start").as_str() {
                Some(text) => CapStore::load(text.as_bytes(), now_s).unwrap(),
                None => CapStore::new(),
            });
            let before = s.clone();
            let args = step.at("args");
            let origin = || args.index(0).text();
            let key = || asset_key(number(args.index(1)), args.index(2).text());
            let effect = match step.at("op").text() {
                "grant" => {
                    let applied = s.grant(
                        origin(),
                        &key(),
                        args.index(3).text(),
                        number(args.index(4)),
                        now_s,
                    );
                    assert_eq!(
                        js_text(applied.value.as_ref().unwrap()),
                        record_of(core.at("result")),
                        "{label}"
                    );
                    applied.effect
                }
                "charge" => {
                    let applied = s.charge(origin(), &key(), args.index(3).text(), now_s);
                    assert_eq!(
                        applied.value.is_some(),
                        matches!(core.at("result"), JsValue::Object(_)),
                        "{label}"
                    );
                    if applied.value.is_some() {
                        last_charge = applied.value;
                    }
                    applied.effect
                }
                "refund" => {
                    let applied = s.refund(last_charge.as_ref().unwrap());
                    assert_eq!(boolean(applied.value), *core.at("result"), "{label}");
                    applied.effect
                }
                "updatePermission" => {
                    let patch = args.index(3);
                    let applied = s.update(
                        origin(),
                        &key(),
                        patch.at("capAmount").as_str(),
                        match patch.at("windowSeconds") {
                            JsValue::Undefined => None,
                            window => Some(number(window)),
                        },
                    );
                    match core.at("result") {
                        JsValue::Undefined => assert!(applied.value.is_none(), "{label}"),
                        result => assert_eq!(
                            js_text(applied.value.as_ref().unwrap()),
                            record_of(result),
                            "{label}"
                        ),
                    }
                    applied.effect
                }
                "revoke" => s.revoke(origin(), &key()).effect,
                "revokeAllForOrigin" => s.revoke_all(origin()).effect,
                "getPermission" => {
                    let active = s.active(origin(), &key(), now_s);
                    assert_eq!(
                        active.is_some(),
                        matches!(core.at("result"), JsValue::Object(_)),
                        "{label}"
                    );
                    Effect::Unchanged
                }
                "getAllPermissions" => {
                    // The caps live at that time.
                    assert_eq!(
                        js_text(&cap_list(&s.live(now_s))),
                        js_text(core.at("result")),
                        "{label}"
                    );
                    Effect::Unchanged
                }
                "reload" => {
                    *s = CapStore::load(s.text().unwrap().as_bytes(), now_s).unwrap();
                    Effect::Unchanged
                }
                other => panic!("{label}: no core operation for {other}"),
            };
            if core.at("wrote") == &boolean(true) {
                assert_eq!(s.text().unwrap(), core.at("text").text(), "{label}");
            } else {
                // The reference wrote nothing: neither does the core.
                assert_eq!(effect, Effect::Unchanged, "{label}");
                if !step.at("op").is("reload") {
                    assert_eq!(*s, before, "{label}");
                }
            }
        }
    }
    assert_eq!(
        deviations.into_iter().collect::<Vec<_>>(),
        ["x402-asset-case", "x402-clock-back"]
    );
}

/// The core's store after reading `bytes`, as getAllPermissions lists it,
/// or why it is unreadable.
fn read(kind: StoreKind, bytes: &[u8]) -> Result<JsValue, Unreadable> {
    let now_s = 1_762_000_000;
    let listed = |records: Result<Vec<&JsValue>, _>| {
        JsValue::Array(records.unwrap().into_iter().cloned().collect())
    };
    Ok(match kind {
        StoreKind::Dapp => listed(DappStore::load(bytes)?.records()),
        StoreKind::Swarm => listed(SwarmStore::load(bytes)?.records()),
        StoreKind::Radicle => listed(RadicleStore::load(bytes)?.records()),
        StoreKind::X402 => cap_list(&CapStore::load(bytes, now_s)?),
    })
}

/// A connect of `https://other.example` at the vectors' clock, on what the
/// core read from `bytes` (an empty store for an unreadable file).
/// Base's USDC, which the generator's x402 grant names in mixed case.
const USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/// The reference's text after its grant, as the core writes it: the cap's
/// key in lowercase (`x402-asset-case`), the only place the asset appears.
fn expected_after(kind: StoreKind, text: &str) -> String {
    match kind {
        StoreKind::X402 => {
            assert!(text.is_empty() || text.contains(USDC), "{text}");
            text.replace(USDC, &USDC.to_lowercase())
        }
        _ => text.to_owned(),
    }
}

fn connect_after(kind: StoreKind, bytes: &[u8]) -> String {
    const OTHER: &str = "https://other.example";
    const T: u64 = 1_762_000_000_000;
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
        // The reference's `grant(other, 8453, USDC, "1", 60)`, the asset
        // in lowercase (`x402-asset-case`).
        StoreKind::X402 => {
            let mut store = CapStore::load(bytes, T / 1000).unwrap_or_default();
            store.grant(OTHER, &asset_key(8453.0, USDC), "1", 60.0, T / 1000);
            store.text().unwrap()
        }
    }
}

#[test]
fn malformed_files() {
    let stores = stores();
    for kind in StoreKind::ALL {
        let cases = stores.at(kind.name()).at("malformed").items();
        let empty = cases
            .iter()
            .find(|c| c.at("id").is("empty-object"))
            .unwrap();
        for case in cases {
            let label = format!("{}/{}", kind.name(), case.at("id").text());
            let bytes = match case.at("hex").as_str() {
                Some(hex) => bytes_of_hex(hex),
                None => case.at("text").text().as_bytes().to_vec(),
            };
            match case.at("core").text() {
                "unreadable" => {
                    assert!(read(kind, &bytes).is_err(), "{label}");
                    // Renamed aside, the store starts empty: a connect (a
                    // grant, for x402) then writes what it writes on an
                    // empty file.
                    assert_eq!(
                        connect_after(kind, &bytes),
                        expected_after(kind, empty.at("afterGrant").at("text").text()),
                        "{label}"
                    );
                }
                "parsed" => {
                    let read = read(kind, &bytes).unwrap();
                    match case.at("loaded").at("json").as_str() {
                        // A lone surrogate's value, as JSON.stringify's text.
                        Some(json) => assert_eq!(read.stringify(), json, "{label}"),
                        None => assert_eq!(
                            js_text(&read),
                            js_text(case.at("loaded").at("value")),
                            "{label}"
                        ),
                    }
                    assert_eq!(
                        connect_after(kind, &bytes),
                        expected_after(kind, case.at("afterGrant").at("text").text()),
                        "{label}"
                    );
                }
                other => panic!("{label}: core {other}"),
            }
        }
        // Where the reference reads a malformed file as empty, as most of
        // them, its next write is the core's after the rename (the
        // reference's file is lost; the core's is kept aside).
        let as_empty = cases
            .iter()
            .filter(|c| {
                c.at("core").is("unreadable") && c.at("afterGrant") == empty.at("afterGrant")
            })
            .count();
        assert!(as_empty >= 5, "{}", kind.name());
    }
}

/// getAllPermissions' order over the generated files, in each site store:
/// V8's sort, with the comparator's NaN read as equal.
#[test]
fn records_sort_as_the_reference() {
    let cases = stores().at("sorts").clone();
    assert!(cases.items().len() >= 24);
    for case in cases.items() {
        let id = case.at("id").text();
        let text = case.at("text").text().as_bytes();
        let expected: Vec<String> = case
            .at("order")
            .items()
            .iter()
            .map(|index| format!("k{}", index.integer()))
            .collect();
        let origins = |records: Vec<&JsValue>| -> Vec<String> {
            records
                .iter()
                .map(|entry| entry.at("origin").text().to_owned())
                .collect()
        };
        let dapp = DappStore::load(text).unwrap();
        assert_eq!(origins(dapp.records().unwrap()), expected, "dapp/{id}");
        let swarm = SwarmStore::load(text).unwrap();
        assert_eq!(origins(swarm.records().unwrap()), expected, "swarm/{id}");
        let radicle = RadicleStore::load(text).unwrap();
        assert_eq!(
            origins(radicle.records().unwrap()),
            expected,
            "radicle/{id}"
        );
    }
}
