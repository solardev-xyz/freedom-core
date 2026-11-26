//! vectors/ledger-grammar.json both ways (design 0016, LDG-1): every APDU
//! the core sends for a case of vectors/ledger.json is admitted by its
//! row at its place, and every row is reached, as often as the grammar
//! file counts; the honest streams, the same-shape schemas, the Safe and
//! x402 changes are the core's own streams for their typed data; the
//! forbidden APDUs are never the core's at their place; the byte families
//! count the core's bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use common::*;
use fc_evm::{Transaction, typed_data_hash};
use fc_ledger::{LedgerPath, Refusal, Scheme};
use serde_json::Value;

/// What a row's APDU must hold, from the case's request and record.
struct Context {
    operation: String,
    path: Vec<u8>,
    /// ledger.accounts: each path in order.
    paths: Vec<Vec<u8>>,
    /// sign.transaction: `P ‖ T`; sign.message: `P ‖ len(m) ‖ m`.
    payload: Vec<u8>,
}

fn context(case: &Value) -> Context {
    let request = &case["request"];
    let operation = case["operation"].as_str().unwrap().to_owned();
    let mut ctx = Context {
        operation: operation.clone(),
        path: Vec::new(),
        paths: Vec::new(),
        payload: Vec::new(),
    };
    match operation.as_str() {
        "ledger.accounts" => {
            let scheme = Scheme::parse(request["scheme"].as_str().unwrap()).unwrap();
            let start = request["start"].as_u64().unwrap();
            for k in 0..request["count"].as_u64().unwrap() {
                ctx.paths
                    .push(LedgerPath::new(scheme, start + k).unwrap().encode());
            }
        }
        "ledger.add" => {
            ctx.path = LedgerPath::parse(request["path"].as_str().unwrap())
                .unwrap()
                .encode();
        }
        _ => {
            ctx.path = account(&case["record"]).path.encode();
            ctx.payload = ctx.path.clone();
            if operation == "sign.transaction" {
                let tx = Transaction::from_json(&request["tx"]).unwrap();
                ctx.payload
                    .extend_from_slice(tx.prepare().unwrap().unsigned());
            }
            if operation == "sign.message" {
                let m = unhex(request["message"].as_str().unwrap());
                ctx.payload
                    .extend_from_slice(&(m.len() as u32).to_be_bytes());
                ctx.payload.extend_from_slice(&m);
            }
        }
    }
    ctx
}

/// The row an APDU of the core's stream is in, or the rule it breaks.
/// `answers[i]` is the answer the APDU at `i` got.
fn admit(
    ctx: &Context,
    apdus: &[Vec<u8>],
    answers: &[Vec<u8>],
    i: usize,
) -> Result<&'static str, String> {
    let apdu = &apdus[i];
    let (header, data) = (&apdu[..4], &apdu[5..]);
    if apdu[4] as usize != data.len() {
        return Err("header: Lc".into());
    }
    match ctx.operation.as_str() {
        "ledger.accounts" => {
            let want = ctx.paths.get(i).ok_or("ended")?;
            (header == [0xe0, 0x02, 0x00, 0x00] && data == want.as_slice())
                .then_some("ledger.accounts")
                .ok_or("path".into())
        }
        "ledger.add" => (i == 0 && header == [0xe0, 0x02, 0x01, 0x00] && data == ctx.path)
            .then_some("ledger.add")
            .ok_or("header".into()),
        operation => {
            if i == 0 {
                return (header == [0xe0, 0x02, 0x00, 0x00] && data == ctx.path)
                    .then_some("signature.first")
                    .ok_or("path".into());
            }
            if i == 1 {
                return (header == [0xb0, 0x01, 0x00, 0x00] && data.is_empty())
                    .then_some("signature.second")
                    .ok_or("header".into());
            }
            match operation {
                "sign.transaction" | "sign.message" => {
                    let ins = if operation == "sign.transaction" {
                        0x04
                    } else {
                        0x08
                    };
                    let p1 = if i == 2 { 0x00 } else { 0x80 };
                    if header != [0xe0, ins, p1, 0x00] {
                        return Err("header".into());
                    }
                    // The pieces so far are the payload's start; the last ends it.
                    let sent: Vec<u8> = apdus[2..=i].iter().flat_map(|a| a[5..].to_vec()).collect();
                    if !ctx.payload.starts_with(&sent) {
                        return Err("payload".into());
                    }
                    if i == apdus.len() - 1 && sent.len() != ctx.payload.len() {
                        return Err("payload: short".into());
                    }
                    if operation == "sign.message" {
                        let first = 150 - ctx.path.len() - 4;
                        let want = if i == 2 {
                            ctx.path.len() + 4 + first.min(ctx.payload.len() - ctx.path.len() - 4)
                        } else {
                            150.min(ctx.payload.len() - (sent.len() - data.len()))
                        };
                        if data.len() != want {
                            return Err("payload: piece size".into());
                        }
                    }
                    Ok(if operation == "sign.transaction" {
                        "sign.transaction"
                    } else {
                        "sign.message"
                    })
                }
                "sign.typed_data" => {
                    let values_started = apdus[2..i].iter().any(|a| a[1] == 0x1c);
                    match header {
                        [0xe0, 0x1a, 0x00, 0x00 | 0xff] if !values_started => {
                            if i == 2 && header[3] != 0x00 {
                                return Err("order".into());
                            }
                            Ok("sign.typed_data.definitions")
                        }
                        [0xe0, 0x1c, 0x00, 0x00 | 0x0f | 0xff] | [0xe0, 0x1c, 0x01, 0xff] => {
                            if i == 2 {
                                return Err("order".into());
                            }
                            Ok("sign.typed_data.values")
                        }
                        [0xe0, 0x0c, 0x00, 0x01] => (i == apdus.len() - 1 && data == ctx.path)
                            .then_some("sign.typed_data.sign")
                            .ok_or("count".into()),
                        [0xe0, 0x0c, 0x00, 0x00] => {
                            // Only after 6D00 to the first E0 1A.
                            let after = i == 3 && answers[2] == [0x6d, 0x00];
                            (after
                                && i == apdus.len() - 1
                                && data.len() == ctx.path.len() + 64
                                && data.starts_with(&ctx.path))
                            .then_some("hash-only")
                            .ok_or("order".into())
                        }
                        _ => Err("header".into()),
                    }
                }
                other => panic!("no operation {other}"),
            }
        }
    }
}

/// Every complete stream the core sends for a case, its answers beside.
fn clean(case: &Value) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let mut op = operation(case).ok()?;
    let mut device = device_for(case);
    let mut answers = Vec::new();
    let run = run(&mut op, |index, apdu| {
        let answer = device.answer(apdu);
        if let Answer::Bytes(bytes) = &answer {
            answers.push(bytes.clone());
        }
        relay(index, apdu, answer)
    });
    Some((run.apdus, answers))
}

#[test]
fn every_apdu_matches_its_row_and_every_row_is_reached() {
    let grammar = grammar();
    let honest: BTreeMap<&str, &Value> = grammar["honest"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| (h["case"].as_str().unwrap(), &h["apdus"]))
        .collect();
    let mut reached: BTreeMap<String, u64> = BTreeMap::new();
    let mut admitted = 0;
    for case in cases() {
        let id = case["id"].as_str().unwrap();
        let Some((apdus, answers)) = clean(case) else {
            continue;
        };
        let ctx = context(case);
        for i in 0..apdus.len() {
            let row = admit(&ctx, &apdus, &answers, i).unwrap_or_else(|rule| {
                panic!("{id}: APDU {i} refused, {rule}: {}", hex(&apdus[i]))
            });
            admitted += 1;
            if honest.contains_key(id) {
                *reached.entry(row.to_owned()).or_default() += 1;
                if id == "typed-safe-tx" || id == "typed-safe-message" {
                    *reached.entry("safe.sign_owner".into()).or_default() += 1;
                }
            }
        }
        if let Some(stream) = honest.get(id) {
            let ours: Vec<String> = apdus.iter().map(|a| hex(a)).collect();
            let theirs: Vec<&str> = stream
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            assert_eq!(ours, theirs, "{id}");
        }
    }
    assert!(admitted > 4000, "{admitted}");
    let want: BTreeMap<String, u64> = grammar["checked"]["reached"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(row, n)| (row.clone(), n.as_u64().unwrap()))
        .collect();
    assert_eq!(reached, want);
    for row in grammar["rows"].as_array().unwrap() {
        let name = row["row"].as_str().unwrap();
        assert!(
            reached.get(name).copied().unwrap_or(0) > 0,
            "no case reaches {name}"
        );
    }
}

/// The honest stream of a case of the grammar file.
fn honest(id: &str) -> Vec<String> {
    grammar()["honest"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["case"] == id)
        .unwrap()["apdus"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect()
}

/// The core's whole stream for other typed data, under a case's record.
fn typed_stream(id: &str, typed: &Value) -> Vec<String> {
    let case = case(id);
    let hash = typed_data_hash(&typed["domain"], &typed["types"], &typed["message"]).unwrap();
    let mut op = typed_operation(account(&case["record"]), typed, &hash).unwrap();
    let mut device = Device::default();
    device.typed_hash = Some(hash);
    let run = run_device(&mut op, &mut device);
    assert!(run.done.is_ok(), "{id}: {:?}", run.done);
    run.apdus.iter().map(|a| hex(a)).collect()
}

#[test]
fn another_schema_of_the_same_shape_is_the_cores_own_stream() {
    let entries = grammar()["same_shape"].as_array().unwrap();
    assert_eq!(entries.len(), 76);
    for entry in entries {
        let id = entry["case"].as_str().unwrap();
        let ours = typed_stream(id, &entry["typed_data"]);
        let theirs: Vec<&str> = entry["apdus"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert_eq!(ours, theirs, "{id}");
        let honest = honest(id);
        assert_eq!(ours.len(), honest.len(), "{id}: the same counts");
        for (a, b) in ours.iter().zip(&honest) {
            assert_eq!(a[..10], b[..10], "{id}: the same headers and lengths");
        }
        assert_ne!(ours, honest, "{id}: other bytes");
    }
}

#[test]
fn each_x402_change_is_the_cores_stream_for_the_changed_authorization() {
    let entries = grammar()["x402_changes"].as_array().unwrap();
    assert_eq!(entries.len(), 99);
    for entry in entries {
        let id = entry["case"].as_str().unwrap();
        let typed = &entry["typed_data"];
        let hash = typed_data_hash(&typed["domain"], &typed["types"], &typed["message"]).unwrap();
        assert_eq!(
            fc_evm::to_hex(&hash),
            entry["hash"].as_str().unwrap(),
            "{id}"
        );
        let ours = typed_stream(id, typed);
        let theirs: Vec<&str> = entry["apdus"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert_eq!(ours, theirs, "{id}: {}", entry["change"]);
        assert_ne!(ours, honest(id), "{id}: {}", entry["change"]);
    }
}

#[test]
fn each_safe_change_leaves_the_honest_stream_where_the_file_says() {
    let entries = grammar()["safe_changes"].as_array().unwrap();
    assert_eq!(entries.len(), 15);
    for entry in entries {
        let id = entry["case"].as_str().unwrap();
        let ours = typed_stream(id, &entry["typed_data"]);
        let honest = honest(id);
        let at = ours.iter().zip(&honest).position(|(a, b)| a != b).unwrap();
        let first = &entry["first_difference"];
        assert_eq!(
            at as u64,
            first["at"].as_u64().unwrap(),
            "{id}: {}",
            entry["change"]
        );
        assert_eq!(
            ours[at],
            first["apdu"].as_str().unwrap(),
            "{id}: {}",
            entry["change"]
        );
    }
}

#[test]
fn the_name_ascii_definitions_are_never_sent() {
    let entries = grammar()["name_ascii"].as_array().unwrap();
    assert_eq!(entries.len(), 24);
    for entry in entries {
        let id = entry["case"].as_str().unwrap();
        assert!(
            matches!(operation(case(id)), Err(Refusal::TypedData(_))),
            "{id}: not refused by 0002's identifier rule"
        );
    }
}

#[test]
fn no_forbidden_apdu_is_the_cores_at_its_place() {
    let entries = grammar()["forbidden"].as_array().unwrap();
    assert_eq!(entries.len(), 147);
    for entry in entries {
        let id = entry["case"].as_str().unwrap();
        let ours = clean(case(id)).unwrap().0;
        assert_eq!(
            ours.iter().map(|a| hex(a)).collect::<Vec<_>>(),
            honest(id),
            "{id}"
        );
        if entry.get("parent").is_some() || entry.get("state").is_some() {
            // The core's own bytes under another parent, or before main's
            // hash_only answer, which the machine never sends before it
            // (tests/answers.rs): main's state decides these.
            continue;
        }
        let at = entry["at"].as_u64().unwrap() as usize;
        let apdu = entry["apdu"].as_str().unwrap();
        match ours.get(at) {
            Some(our) => assert_ne!(hex(our), apdu, "{id}: {}", entry["what"]),
            None => assert_eq!(entry["rule"], "ended", "{id}"),
        }
    }
}

#[test]
fn the_byte_families_count_the_cores_bytes() {
    let mut typed = 0u64;
    let mut pieces = 0u64;
    for entry in grammar()["honest"].as_array().unwrap() {
        let id = entry["case"].as_str().unwrap();
        let apdus: Vec<Vec<u8>> = entry["apdus"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| unhex(a.as_str().unwrap()))
            .collect();
        let path_len = match entry["operation"].as_str().unwrap() {
            "sign.transaction" | "sign.message" => account(&case(id)["record"]).path.encode().len(),
            _ => 0,
        };
        for apdu in &apdus {
            match apdu[..2] {
                [0xe0, 0x1a] | [0xe0, 0x1c] => typed += apdu[5..].len() as u64,
                [0xe0, 0x04] | [0xe0, 0x08] => {
                    let past = if apdu[2] == 0x00 { path_len } else { 0 };
                    pieces += (apdu[5..].len() - past) as u64;
                }
                _ => {}
            }
        }
    }
    let families = grammar()["byte_families"].as_array().unwrap();
    let count = |name: &str| {
        families.iter().find(|f| f["family"] == name).unwrap()["count"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(typed, count("typed-data-byte"));
    assert_eq!(pieces, count("piece-byte"));
}
