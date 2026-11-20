//! Replays vectors/stores.json's `intents`, which the pinned reference's
//! intent-store.js produced: after every step of every run, the file's
//! records load to the same verdict, the same rewritten file, views and
//! usage; every damaged file gives the reference's reason.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_json::JsString;
use fc_json::JsValue;
use fc_wallet_state::intents::{
    Intents, LIMITS, Limits, Refusal, Room, Write, handoff_line_max, line_bytes, outcome_line_max,
    terminal_line_max,
};

static UNDEFINED: JsValue = JsValue::Undefined;

fn intents() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/stores.json");
    let text = std::fs::read_to_string(path).expect("vectors/stores.json");
    let all = fc_json::parse(&text).expect("stores.json parses");
    all.get("intents").expect("an intents section").clone()
}

fn field<'a>(value: &'a JsValue, key: &str) -> &'a JsValue {
    value.get(key).unwrap_or(&UNDEFINED)
}

fn items(value: &JsValue) -> &[JsValue] {
    value.as_array().expect("an array")
}

fn number(value: &JsValue) -> f64 {
    match value {
        JsValue::Number(n) => *n,
        other => panic!("not a number: {other:?}"),
    }
}

fn limits_of(value: &JsValue) -> Limits {
    let mut limits = LIMITS;
    let over = |key: &str| value.get(key).map(|v| number(v) as usize);
    if let Some(n) = over("tombstones") {
        limits.tombstones = n;
    }
    if let Some(n) = over("heldPerAccount") {
        limits.held_per_account = n;
    }
    if let Some(n) = over("held") {
        limits.held = n;
    }
    if let Some(n) = over("hashesPerIntent") {
        limits.hashes_per_intent = n;
    }
    if let Some(n) = over("openHandoffsPerIntent") {
        limits.open_handoffs_per_intent = n;
    }
    if let Some(n) = over("rawBytes") {
        limits.raw_bytes = n;
    }
    if let Some(n) = over("journalBytes") {
        limits.journal_bytes = n as u64;
    }
    limits
}

fn texts(values: &[JsValue]) -> Vec<String> {
    values.iter().map(JsValue::stringify).collect()
}

#[test]
fn the_limits_and_line_maxima_are_the_references() {
    let vectors = intents();
    let limits = field(&vectors, "limits");
    let pairs = [
        ("heldPerAccount", LIMITS.held_per_account as f64),
        ("held", LIMITS.held as f64),
        ("hashesPerIntent", LIMITS.hashes_per_intent as f64),
        (
            "openHandoffsPerIntent",
            LIMITS.open_handoffs_per_intent as f64,
        ),
        ("tombstones", LIMITS.tombstones as f64),
        ("rawBytes", LIMITS.raw_bytes as f64),
        ("journalBytes", LIMITS.journal_bytes as f64),
        ("readBytes", LIMITS.read_bytes as f64),
    ];
    for (key, value) in pairs {
        assert_eq!(number(field(limits, key)), value, "LIMITS.{key}");
    }
    let line_max = field(&vectors, "line_max");
    assert_eq!(
        number(field(line_max, "handoff")),
        handoff_line_max() as f64
    );
    assert_eq!(
        number(field(line_max, "outcome")),
        outcome_line_max() as f64
    );
    assert_eq!(
        number(field(line_max, "terminal")),
        terminal_line_max() as f64
    );
}

fn check_load(name: &str, records: &[JsValue], load: &JsValue, limits: Limits) {
    let result = Intents::load(records, limits);
    let reason = field(load, "reason");
    if let JsValue::String(reason) = reason {
        let damaged = result
            .err()
            .unwrap_or_else(|| panic!("{name}: loaded, the reference didn't"));
        assert_eq!(damaged.0, reason.as_str(), "{name}: the reason");
        return;
    }
    let loaded = result.unwrap_or_else(|e| panic!("{name}: {e}"));
    let mut store = loaded.intents;
    let compacted = field(load, "compacted");
    assert_eq!(
        loaded.compact,
        !matches!(compacted, JsValue::Null),
        "{name}: rewrites the file"
    );
    let file = if loaded.compact {
        let records = store.compaction();
        assert_eq!(
            texts(&records),
            texts(items(compacted)),
            "{name}: the rewritten file"
        );
        store.compacted();
        records
    } else {
        records.to_vec()
    };
    let list = field(load, "list");
    let ours = store.list();
    assert_eq!(texts(&ours), texts(items(list)), "{name}: list()");
    for (view, id) in ours
        .iter()
        .zip(items(list).iter().map(|v| field(v, "intentId")))
    {
        let id = id.as_str().unwrap();
        assert_eq!(store.get(id).as_ref(), Some(view), "{name}: get({id})");
    }
    assert_eq!(store.get("00000000-unknown"), None);
    let held: Vec<JsValue> = store
        .held()
        .iter()
        .map(|v| field(v, "intentId").clone())
        .collect();
    assert_eq!(
        texts(&held),
        texts(items(field(load, "held"))),
        "{name}: held()"
    );
    for entry in items(field(load, "by_key")) {
        let key = field(entry, "key").as_js_string();
        let ours = store
            .by_key(key)
            .map(|v| field(&v, "intentId").clone())
            .unwrap_or(JsValue::Null);
        assert_eq!(&ours, field(entry, "id"), "{name}: byKey({key:?})");
    }
    for entry in items(field(load, "held_nonces")) {
        let sender = field(entry, "sender").as_str().unwrap();
        let nonces = store.held_nonces(
            number(field(entry, "chain_id")),
            &sender.to_ascii_uppercase().replace("0X", "0x"),
        );
        let expected: Vec<f64> = items(field(entry, "nonces")).iter().map(number).collect();
        assert_eq!(nonces, expected, "{name}: heldNonces({sender})");
    }
    for (view, refusal) in items(list).iter().zip(items(field(load, "void_refusal"))) {
        let id = field(view, "intentId").as_str().unwrap();
        let ours = store
            .void_refusal(id, "00000000-0000-4000-8000-000000900001")
            .unwrap();
        assert_eq!(
            ours.as_deref(),
            refusal.as_str(),
            "{name}: voidRefusal({id})"
        );
    }
    let usage = field(load, "usage");
    let size: usize = file.iter().map(line_bytes).sum();
    assert_eq!(
        number(field(usage, "file")),
        size as f64,
        "{name}: the file's size"
    );
    assert_eq!(
        number(field(usage, "owed")),
        store.owed() as f64,
        "{name}: owed"
    );
    assert_eq!(
        number(field(usage, "budget")),
        store.budget() as f64,
        "{name}: budget"
    );
    assert_eq!(
        number(field(usage, "limit")),
        store.limits().journal_bytes as f64
    );
}

#[test]
fn every_step_of_every_run_loads_as_the_reference_loads_it() {
    let vectors = intents();
    let mut steps = 0;
    for run in items(field(&vectors, "runs")) {
        let mut limits = limits_of(field(run, "limits"));
        for (i, step) in items(field(run, "steps")).iter().enumerate() {
            if let JsValue::Object(_) = field(field(step, "args"), "limits") {
                limits = limits_of(field(field(step, "args"), "limits"));
            }
            let name = format!(
                "{} step {i} ({})",
                field(run, "name").as_str().unwrap(),
                field(step, "op").as_str().unwrap()
            );
            check_load(
                &name,
                items(field(step, "records")),
                field(step, "load"),
                limits,
            );
            steps += 1;
        }
    }
    assert!(steps >= 60, "{steps} steps");
}

#[test]
fn every_damaged_file_gives_the_references_reason() {
    let vectors = intents();
    let damaged = items(field(&vectors, "damaged"));
    assert!(damaged.len() >= 70);
    for case in damaged {
        let name = field(case, "name").as_str().unwrap();
        let records = items(field(case, "records"));
        let result = Intents::load(records, LIMITS);
        match field(case, "reason") {
            JsValue::String(reason) => {
                let damaged = result
                    .err()
                    .unwrap_or_else(|| panic!("{name}: loaded, the reference didn't"));
                assert_eq!(damaged.0, reason.as_str(), "{name}");
            }
            _ => assert!(result.is_ok(), "{name}: {:?}", result.err()),
        }
    }
}

/// The file after compaction, which the state then folds (`compactNow`).
fn compact(store: &mut Intents) -> Vec<JsValue> {
    let records = store.compaction();
    store.compacted();
    records
}

fn size(file: &[JsValue]) -> u64 {
    file.iter().map(|r| line_bytes(r) as u64).sum()
}

/// `write(record, lock, { admitted })` once the record is checked: the
/// room it needs (compacting first if it must), the append, the apply.
fn append(store: &mut Intents, file: &mut Vec<JsValue>, write: Write) -> Result<(), Refusal> {
    if store.room(&write, size(file), false)? == Room::Compact {
        *file = compact(store);
        assert_eq!(store.room(&write, size(file), true)?, Room::Fits);
    }
    file.push(write.record().clone());
    let id = write.record().get("intent_id").cloned();
    let answer = store.apply(write);
    let id = id.and_then(|id| id.as_str().map(str::to_owned)).unwrap();
    assert_eq!(
        answer,
        store.get(&id),
        "a write answers the intent after it"
    );
    Ok(())
}

/// One step of a run, through the live writes: the refusal, or the file
/// after it.
fn live_step(
    store: &mut Intents,
    file: &mut Vec<JsValue>,
    step: &JsValue,
    limits: &mut Limits,
) -> Result<(), Refusal> {
    let op = field(step, "op").as_str().unwrap();
    let run = field(step, "run").as_js_string().unwrap().clone();
    let at = number(field(step, "at"));
    let call = field(step, "call");
    let uuids = items(field(step, "uuids"));
    let new_id = uuids
        .first()
        .and_then(JsValue::as_js_string)
        .cloned()
        .unwrap_or_else(|| JsString::from("not-named-by-the-store"));
    let lock = matches!(field(call, "lock"), JsValue::Bool(true));
    let write = match op {
        "restart" => {
            // Other limits for the rest of the run, if it brings them.
            if let JsValue::Object(_) = field(field(step, "args"), "limits") {
                *limits = limits_of(field(field(step, "args"), "limits"));
            }
            let loaded = Intents::load(file, *limits).map_err(|d| panic!("restart: {d}"))?;
            *store = loaded.intents;
            if loaded.compact {
                *file = compact(store);
            }
            return Ok(());
        }
        "compact" => {
            *file = compact(store);
            return Ok(());
        }
        "withdrawOrigin" => {
            let id = field(call, "intentId").as_str().unwrap();
            let withdrawn = store.withdraw_origin(id);
            assert_eq!(
                withdrawn.is_some(),
                matches!(field(call, "result"), JsValue::Bool(true))
            );
            if withdrawn.is_some() {
                *file = compact(store);
            }
            return Ok(());
        }
        "commit" => store.commit(&run, at, &new_id, call)?,
        "handoff" => {
            let write = store.handoff(&run, at, &new_id, call)?;
            let hash = write
                .record()
                .get("hash")
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            let handoff_id = write.record().get("handoff_id").cloned().unwrap();
            let id = field(call, "intentId").as_str().unwrap().to_owned();
            append(store, file, write)?;
            // The reference's answer: the handoff, its hash and exactly the
            // bytes kept for that hash (not the latest, for an original
            // handed off after a replacement).
            let result = field(call, "result");
            assert_eq!(&handoff_id, field(result, "handoffId"), "a handoff's id");
            assert_eq!(
                hash,
                field(result, "hash").as_str().unwrap(),
                "a handoff's hash"
            );
            assert_eq!(
                store.signed(&id, &hash),
                Some(field(result, "raw").as_str().unwrap()),
                "a handoff's bytes"
            );
            return Ok(());
        }
        "outcome" => match store.outcome(&run, at, call)? {
            Some(write) => write,
            None => return Ok(()),
        },
        "settle" => store.settle(&run, at, call)?,
        "retire" => store.retire(&run, at, call, lock)?,
        "track" => store.track(&run, at, call)?,
        "void" => {
            let write = store.void(&run, at, call, lock)?;
            append(store, file, write)?;
            *file = compact(store);
            return Ok(());
        }
        other => panic!("unknown op {other}"),
    };
    append(store, file, write)
}

#[test]
fn every_step_of_every_run_writes_as_the_reference_writes_it() {
    let vectors = intents();
    let mut refused = 0;
    let mut type_errors = 0;
    let mut not_latest = 0;
    for run in items(field(&vectors, "runs")) {
        let mut limits = limits_of(field(run, "limits"));
        let mut store = Intents::load(&[], limits).unwrap().intents;
        let mut file: Vec<JsValue> = Vec::new();
        for (i, step) in items(field(run, "steps")).iter().enumerate() {
            let name = format!(
                "{} step {i} ({})",
                field(run, "name").as_str().unwrap(),
                field(step, "op").as_str().unwrap()
            );
            let result = live_step(&mut store, &mut file, step, &mut limits);
            match (result, field(step, "refusal")) {
                (Ok(()), JsValue::Null) => {}
                (Err(ours), JsValue::Null) => panic!("{name}: refused {ours:?}"),
                (Ok(()), theirs) => panic!("{name}: written, refused as {theirs:?}"),
                (Err(ours), theirs) => {
                    assert_eq!(ours.code, field(theirs, "code").as_str().unwrap(), "{name}");
                    // JavaScript's own TypeError: no code, V8's message.
                    type_errors += usize::from(ours.code.is_empty());
                    assert_eq!(
                        ours.message,
                        field(theirs, "message").as_str().unwrap(),
                        "{name}"
                    );
                    refused += 1;
                }
            }
            assert_eq!(
                texts(&file),
                texts(items(field(step, "records"))),
                "{name}: the file"
            );
            // None after a quiet step: nothing sizes the snapshots then.
            let live = field(step, "live");
            if matches!(live, JsValue::Null) {
                continue;
            }
            let list = store.list();
            assert_eq!(
                texts(&list),
                texts(items(field(live, "list"))),
                "{name}: list()"
            );
            // An original handed off after its replacement: its bytes are
            // not the latest, which `signed` must not answer instead.
            if field(step, "op").as_str() == Some("handoff")
                && matches!(field(step, "refusal"), JsValue::Null)
            {
                let call = field(step, "call");
                let latest = items(field(live, "list"))
                    .iter()
                    .find(|v| field(v, "intentId") == field(call, "intentId"))
                    .map(|v| field(v, "raw"));
                not_latest += usize::from(latest != Some(field(field(call, "result"), "raw")));
            }
            let usage = field(live, "usage");
            assert_eq!(number(field(usage, "file")), size(&file) as f64, "{name}");
            assert_eq!(
                number(field(usage, "owed")),
                store.owed() as f64,
                "{name}: owed"
            );
            assert_eq!(
                number(field(usage, "budget")),
                store.budget() as f64,
                "{name}: budget"
            );
            let run_id = field(step, "run").as_str().unwrap();
            for (view, refusal) in list.iter().zip(items(field(live, "void_refusal"))) {
                let id = field(view, "intentId").as_str().unwrap();
                let ours = store.void_refusal(id, run_id).unwrap();
                assert_eq!(
                    ours.as_deref(),
                    refusal.as_str(),
                    "{name}: voidRefusal({id})"
                );
            }
        }
    }
    assert!(refused >= 25, "{refused} refusals");
    // settle's truthy `hashes` that isn't an array, retire's hash and
    // handoff's intent id whose `${}` throws.
    assert_eq!(type_errors, 3, "JavaScript's own TypeErrors");
    // The lifecycle's original, handed off after its replacement.
    assert!(not_latest >= 1, "no handoff of bytes not the latest");
}

/// `withdrawOrigin`'s rollback when the compaction that records it fails
/// (`restore_origin`): the intent is as it was, its view, the file a
/// compaction writes and its snapshot's size, whether that size was cached
/// before the withdrawal or is first taken after it.
#[test]
fn a_restored_origin_leaves_the_intent_as_it_was() {
    let vectors = intents();
    let run = items(field(&vectors, "runs"))
        .iter()
        .find(|run| field(run, "name").as_str() == Some("the file's budget"))
        .unwrap();
    let limits = limits_of(field(run, "limits"));
    // A committed with its long origin.
    let step = &items(field(run, "steps"))[0];
    let records = items(field(step, "records"));
    let id = field(&records[0], "intent_id").as_str().unwrap();
    let fresh = || Intents::load(records, limits).unwrap().intents;

    // Sized first: the size stays cached through the withdrawal.
    let mut store = fresh();
    let view = store.get(id).unwrap();
    assert!(field(field(&view, "context"), "origin").as_str().is_some());
    let budget = store.budget();
    assert_eq!(
        budget as f64,
        number(field(field(field(step, "load"), "usage"), "budget")),
        "the reference's budget for the file"
    );
    let file = texts(&store.compaction());
    let withdrawn = store.withdraw_origin(id).expect("an origin to withdraw");
    assert!(matches!(
        field(field(&store.get(id).unwrap(), "context"), "origin"),
        JsValue::Null
    ));
    assert_ne!(texts(&store.compaction()), file);
    assert_eq!(store.budget(), budget, "the old size, cached");
    store.restore_origin(withdrawn.clone());
    assert_eq!(store.get(id), Some(view.clone()), "its view");
    assert_eq!(
        texts(&store.compaction()),
        file,
        "the file compaction writes"
    );
    // The budget is read only after a second withdrawal: a restore that
    // dropped the cached size would size the intent without its origin.
    assert_eq!(
        store.withdraw_origin(id),
        Some(withdrawn),
        "the same origin"
    );
    assert_eq!(store.budget(), budget, "still the size cached at first");

    // Withdrawn before it is sized and put back: sized with its origin.
    let mut store = fresh();
    let withdrawn = store.withdraw_origin(id).unwrap();
    store.restore_origin(withdrawn);
    assert_eq!(store.budget(), budget, "sized with its origin");
    assert_eq!(store.get(id), Some(view));
    assert_eq!(texts(&store.compaction()), file);
}
