//! Replays vectors/stores.json's `vault_meta`, which the pinned reference's
//! identity-manager.js produced: every step's `core` operation, from the
//! run's start text, gives the reference's answer, writes when it writes,
//! and leaves the same text byte for byte; and each malformed file reads as
//! the design says, with what the reference loads from the ones the core
//! parses.
//!
//! The vectors are read as JSON.parse reads them (fc-json), so a recorded
//! lone surrogate stays one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_json::JsValue;
use fc_wallet_state::vault_meta::{
    Changed, Device, Failed, Kind, Refusal, SafeParams, Unreadable, VaultMeta,
};

static UNDEFINED: JsValue = JsValue::Undefined;

fn vectors() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/stores.json");
    let text = std::fs::read_to_string(path).expect("vectors/stores.json");
    fc_json::parse(&text).expect("stores.json parses")
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

fn boolean(value: &JsValue) -> bool {
    match value {
        JsValue::Bool(b) => *b,
        other => panic!("not a boolean: {other:?}"),
    }
}

fn text_of(meta: &VaultMeta) -> JsValue {
    meta.text()
        .map_or(JsValue::Null, |text| JsValue::string(text.as_str()))
}

/// The step's call to `fn`, if it made one.
fn call<'a>(step: &'a JsValue, name: &str) -> Option<&'a JsValue> {
    items(field(step, "calls"))
        .iter()
        .find(|call| field(call, "fn").as_str() == Some(name))
}

/// The answer the step's `vault.addresses` call gave for `accounts`, as
/// the closures take it: none while the vault is locked.
fn derived(step: &JsValue, accounts: &[f64]) -> Option<Vec<(f64, String)>> {
    let call = call(step, "vault.addresses").expect("the reference asked the identity core");
    let asked: Vec<f64> = items(field(&items(field(call, "args"))[0], "accounts"))
        .iter()
        .map(number)
        .collect();
    assert_eq!(asked, accounts, "the indices asked");
    if call.get("error").is_some() {
        return None;
    }
    Some(
        items(field(field(call, "answer"), "user_wallets"))
            .iter()
            .map(|wallet| {
                (
                    number(field(wallet, "account")),
                    text(field(wallet, "address")).to_owned(),
                )
            })
            .collect(),
    )
}

/// What an operation answered: a value, or a refusal.
enum Answer {
    Value(JsValue, bool),
    Refused(Refusal),
}

fn changed<T>(changed: Changed<T>, value: impl FnOnce(T) -> JsValue) -> Answer {
    Answer::Value(value(changed.value), changed.wrote)
}

fn answer<T>(result: Result<Changed<T>, Refusal>, value: impl FnOnce(T) -> JsValue) -> Answer {
    match result {
        Ok(done) => changed(done, value),
        Err(refusal) => Answer::Refused(refusal),
    }
}

fn unit(_: ()) -> JsValue {
    JsValue::Null
}

fn kind(name: &JsValue) -> Kind {
    Kind::from_type_name(text(name)).expect("a device kind")
}

fn device(name: &JsValue) -> Device {
    match text(name) {
        "ledger" => Device::Ledger,
        "remote" => Device::Remote,
        other => panic!("not a device: {other}"),
    }
}

/// Runs the step's `core` operation on `meta`.
fn run(meta: &mut VaultMeta, step: &JsValue, core: &JsValue) -> Answer {
    let args = items(field(core, "args"));
    let arg = |i: usize| args.get(i).unwrap_or(&UNDEFINED);
    match text(field(core, "op")) {
        "new_vault" => {
            let addresses = arg(2);
            answer(
                meta.new_vault(
                    boolean(arg(0)),
                    number(arg(1)) as i64,
                    text(field(addresses, "user_wallet")),
                    text(field(addresses, "bee_wallet")),
                ),
                unit,
            )
        }
        "migrate_addresses" => {
            let addresses = arg(0);
            changed(
                meta.migrate_addresses(
                    text(field(addresses, "user_wallet")),
                    text(field(addresses, "bee_wallet")),
                ),
                unit,
            )
        }
        "list" => {
            let mut asked = false;
            let listed = meta
                .list(|accounts| {
                    asked = true;
                    Ok::<_, ()>(derived(step, accounts))
                })
                .expect("no derive error");
            assert_eq!(
                asked,
                call(step, "vault.addresses").is_some(),
                "asked the identity core"
            );
            changed(listed, JsValue::Array)
        }
        "record" => Answer::Value(meta.record(number(arg(0))).unwrap_or(JsValue::Null), false),
        "find_by_address" => {
            Answer::Value(meta.find_by_address(arg(0)).unwrap_or(JsValue::Null), false)
        }
        "next_hardware_index" => Answer::Value(
            JsValue::Number(meta.next_hardware_index().expect("a file")),
            false,
        ),
        "active_index" => Answer::Value(JsValue::Number(meta.active_index()), false),
        "add_mnemonic" => {
            let mut asked = false;
            let result = meta.add_mnemonic(boolean(arg(0)), arg(1), |index| {
                asked = true;
                Ok::<_, ()>(derived(step, &[index]).map(|mut wallets| wallets.remove(0).1))
            });
            assert_eq!(
                asked,
                call(step, "vault.addresses").is_some(),
                "asked the identity core"
            );
            match result {
                Ok(done) => changed(done, |value| value),
                Err(Failed::Refused(refusal)) => Answer::Refused(refusal),
                Err(Failed::Derive(())) => panic!("no derive error"),
            }
        }
        "add_device" => answer(
            meta.add_device(kind(arg(0)), arg(1), arg(2), arg(3)),
            |value| value,
        ),
        "add_ledger" => answer(meta.add_ledger(arg(0), arg(1), arg(2)), |value| value),
        "add_remote" => answer(meta.add_remote(arg(0), arg(1)), |value| value),
        "record_address_check" => changed(
            meta.record_address_check(device(arg(0)), number(arg(1)), boolean(arg(2))),
            |state| state.map_or(JsValue::Null, JsValue::string),
        ),
        "add_safe" => {
            let params = arg(1);
            answer(
                meta.add_safe(
                    arg(0),
                    SafeParams {
                        address: field(params, "address"),
                        owners: field(params, "owners"),
                        threshold: field(params, "threshold"),
                        salt_nonce: field(params, "saltNonce"),
                    },
                ),
                |value| value,
            )
        }
        "mark_safe_deployed" => answer(
            meta.mark_safe_deployed(number(arg(0)), number(arg(1))),
            unit,
        ),
        "set_active" => answer(meta.set_active(number(arg(0))), unit),
        "rename" => answer(meta.rename(number(arg(0)), arg(1)), unit),
        "remove" => {
            let origins: Vec<String> = items(arg(1))
                .iter()
                .map(|origin| text(origin).to_owned())
                .collect();
            answer(meta.remove(number(arg(0)), &origins), |removal| {
                // A Safe's approvals, pending entry and session end with it.
                assert_eq!(
                    removal.safe,
                    call(step, "safe.endSafe").is_some(),
                    "the Safe's cleanup"
                );
                JsValue::Null
            })
        }
        other => panic!("no such operation: {other}"),
    }
}

/// The text of a value as JS writes it, so values JS holds alike compare
/// alike (a member holding `undefined` is left out).
fn js(value: &JsValue) -> String {
    value.stringify()
}

#[test]
fn runs() {
    let vectors = vectors();
    let runs = items(field(field(&vectors, "vault_meta"), "runs"));
    assert!(runs.len() >= 28, "every run is replayed");
    let mut steps_replayed = 0;
    for run_ in runs {
        let id = text(field(run_, "id"));
        let mut meta = match field(run_, "start") {
            JsValue::Null => VaultMeta::none(),
            start => VaultMeta::load(text(start).as_bytes())
                .unwrap_or_else(|e| panic!("{id}: start {e}")),
        };
        for (i, step) in items(field(run_, "steps")).iter().enumerate() {
            let at = format!("{id} step {i} ({})", text(field(step, "op")));
            let core = field(step, "core");
            let expected_text = field(step, "text");
            let wrote = boolean(field(step, "wrote"));
            if matches!(core, JsValue::Null) {
                // Main refuses before the core is asked.
                assert!(step.get("error").is_some(), "{at}: main's refusal");
                assert!(!wrote, "{at}");
                assert_eq!(&text_of(&meta), expected_text, "{at}");
                continue;
            }
            let before = text_of(&meta);
            match run(&mut meta, step, core) {
                Answer::Value(value, ours) => {
                    assert!(
                        step.get("error").is_none(),
                        "{at}: the reference refused: {:?}",
                        step.get("error")
                    );
                    let expected = field(step, "result");
                    // createNewVault's answer is the vault's mnemonic.
                    if text(field(step, "op")) != "createNewVault" {
                        assert_eq!(js(&value), js(expected), "{at}: result");
                    }
                    assert_eq!(ours, wrote, "{at}: wrote");
                }
                Answer::Refused(refusal) => {
                    let error = field(step, "error");
                    assert!(step.get("result").is_none(), "{at}: refused {refusal:?}");
                    assert_eq!(
                        refusal.message,
                        text(field(error, "message")),
                        "{at}: message"
                    );
                    let code = match field(error, "code") {
                        JsValue::Null => None,
                        code => Some(text(code)),
                    };
                    assert_eq!(refusal.code, code, "{at}: code");
                    assert!(!wrote, "{at}");
                    assert_eq!(text_of(&meta), before, "{at}: a refusal changes nothing");
                }
            }
            assert_eq!(&text_of(&meta), expected_text, "{at}: text");
            steps_replayed += 1;
        }
    }
    assert!(steps_replayed > 150, "{steps_replayed} steps");
}

#[test]
fn every_text_reads_back_byte_for_byte() {
    let vectors = vectors();
    let mut texts = 0;
    for run_ in items(field(field(&vectors, "vault_meta"), "runs")) {
        let starts = std::iter::once(field(run_, "start"));
        let after = items(field(run_, "steps"))
            .iter()
            .map(|step| field(step, "text"));
        for value in starts.chain(after) {
            let JsValue::String(t) = value else { continue };
            let meta = VaultMeta::load(t.as_str().as_bytes()).expect("the reference's text reads");
            assert_eq!(meta.text().as_deref(), Some(t.as_str()));
            texts += 1;
        }
    }
    assert!(texts > 100, "{texts} texts");
}

fn bytes_of(case: &JsValue) -> Vec<u8> {
    if let Some(hex) = case.get("hex") {
        let hex = text(hex);
        return (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
    }
    if let Some(fill) = case.get("fill") {
        let open = text(field(fill, "open"));
        let close = text(field(fill, "close"));
        let bytes = number(field(fill, "bytes")) as usize;
        let pad = text(field(fill, "char")).repeat(bytes - open.len() - close.len());
        return format!("{open}{pad}{close}").into_bytes();
    }
    // A lone surrogate never reaches a file's bytes: every malformed text is
    // well formed.
    let JsValue::String(t) = field(case, "text") else {
        panic!("no text")
    };
    assert!(t.is_well_formed());
    t.as_str().as_bytes().to_vec()
}

#[test]
fn malformed() {
    let vectors = vectors();
    let cases = items(field(field(&vectors, "vault_meta"), "malformed"));
    assert!(cases.len() >= 30);
    assert_eq!(
        number(field(&vectors, "max_file_bytes")) as usize,
        fc_wallet_state::vault_meta::MAX_FILE_BYTES
    );
    for case in cases {
        let id = text(field(case, "id"));
        let bytes = bytes_of(case);
        match text(field(case, "core")) {
            "unreadable" => {
                let error: Unreadable = VaultMeta::load(&bytes).expect_err(id);
                assert_eq!(error.reason(), text(field(case, "reason")), "{id}");
            }
            "parsed" => {
                let mut meta = VaultMeta::load(&bytes).unwrap_or_else(|e| panic!("{id}: {e}"));
                let value = meta.value().expect("a meta");
                let loaded = field(case, "loaded");
                match loaded.get("json") {
                    Some(json) => assert_eq!(value.stringify(), text(json), "{id}: loaded"),
                    None => {
                        let keys: Vec<&str> =
                            items(field(loaded, "keys")).iter().map(text).collect();
                        let JsValue::Object(props) = value else {
                            panic!("{id}")
                        };
                        assert_eq!(
                            props.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
                            keys,
                            "{id}"
                        );
                        let pad = value
                            .get("pad")
                            .and_then(JsValue::as_js_string)
                            .expect("pad");
                        assert_eq!(
                            pad.utf16_len(),
                            number(field(loaded, "padLength")) as usize,
                            "{id}"
                        );
                    }
                }
                assert_eq!(
                    meta.active_index(),
                    number(field(case, "active")),
                    "{id}: active"
                );
                // A locked list: the identity core answers no addresses.
                let listed = field(case, "listed");
                let ours = meta.list(|_| Ok::<_, ()>(None)).expect("no derive error");
                assert_eq!(
                    js(&JsValue::Array(ours.value)),
                    js(field(listed, "result")),
                    "{id}: listed"
                );
                assert_eq!(
                    ours.wrote,
                    boolean(field(listed, "wrote")),
                    "{id}: list wrote"
                );
            }
            other => panic!("{id}: {other}"),
        }
    }
}
