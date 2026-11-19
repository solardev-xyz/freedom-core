//! `vectors/sqlite.json`'s `payments`, replayed: each of the reference's
//! operations on one database, and each legacy import's rows, through
//! [`Payments`] on a database [`crate::sqlite::open`] created. After every
//! step the table must hold what the reference's left, cell for cell, with
//! SQLite's type for each, and the step must answer what the reference
//! answered or throw what it threw.

use std::path::PathBuf;

use fc_json::JsValue;
use fc_wallet_state::payments::{COLUMNS, Cell, Row};

use super::{Error, Payments, SCHEMA};
use crate::sqlite;

fn vectors() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sqlite.json");
    let text = std::fs::read_to_string(path).unwrap();
    fc_json::parse(&text).unwrap().get("payments").cloned().unwrap()
}

fn fresh() -> (tempfile::TempDir, Payments) {
    let dir = tempfile::tempdir().unwrap();
    let conn = sqlite::open(&dir.path().join("payment-history.sqlite"), &SCHEMA).unwrap();
    (dir, Payments::new(conn))
}

fn object(props: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(props.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

/// The table as the generator reads it: each column `[typeof, value]`, an
/// INTEGER as its decimal text.
fn table(store: &Payments) -> JsValue {
    let rows = super::rows(&store.conn, &statement("SELECT * FROM payments ORDER BY id")).unwrap();
    JsValue::Array(
        rows.iter()
            .map(|row| {
                object(
                    COLUMNS
                        .iter()
                        .zip(row)
                        .map(|(column, cell)| {
                            let (kind, value) = match cell {
                                Cell::Null => ("null", JsValue::Null),
                                Cell::Integer(n) => ("integer", JsValue::string(n.to_string())),
                                Cell::Real(n) => ("real", JsValue::Number(*n)),
                                Cell::Text(text) => ("text", JsValue::string(text.as_str())),
                                Cell::Blob(_) => panic!("a blob"),
                            };
                            (*column, JsValue::Array(vec![JsValue::string(kind), value]))
                        })
                        .collect(),
                )
            })
            .collect(),
    )
}

fn statement(sql: &str) -> fc_wallet_state::payments::Statement {
    fc_wallet_state::payments::Statement { sql: sql.to_owned(), params: Vec::new() }
}

/// A row as better-sqlite3's `all()` answers it: `{ column: value }`.
fn raw(row: &Row) -> JsValue {
    object(COLUMNS.iter().zip(row).map(|(column, cell)| (*column, cell.to_js().unwrap())).collect())
}

fn number(n: usize) -> JsValue {
    JsValue::Number(f64::from(u32::try_from(n).unwrap()))
}

fn now(step: &JsValue) -> f64 {
    match step.get("now") {
        Some(JsValue::Number(n)) => *n,
        other => panic!("now: {other:?}"),
    }
}

fn run(store: &mut Payments, op: &str, args: &[JsValue], now_ms: f64) -> Result<JsValue, Error> {
    let arg = |i: usize| args.get(i).cloned().unwrap_or(JsValue::Undefined);
    match op {
        "append" => store.append(&arg(0), now_ms),
        "update" => store.update(&arg(0), &arg(1), now_ms),
        "markConfirmed" => store.mark_confirmed(&arg(0), &arg(1), now_ms),
        "markFailed" => store.mark_failed(&arg(0), &arg(1), now_ms),
        "markDropped" => store.mark_dropped(&arg(0), now_ms),
        // The reference's setDroppedSeenAt answers nothing.
        "setDroppedSeen" => store.set_dropped_seen(&arg(0), &arg(1), now_ms).map(|_| JsValue::Null),
        "pending" => store.pending().map(|rows| JsValue::Array(rows.iter().map(raw).collect())),
        "getRecent" => store.get_recent(&arg(0)).map(JsValue::Array),
        "getCount" => store.get_count(&arg(0)),
        "getById" => store.get_by_id(&arg(0)),
        "clear" => store.clear().map(number),
        other => panic!("unknown op {other}"),
    }
}

fn check_result(context: &str, got: Result<JsValue, Error>, expected: &JsValue) {
    match (expected.get("ok"), expected.get("error"), got) {
        (Some(ok), None, Ok(got)) => assert_eq!(&got, ok, "{context}: answer"),
        (None, Some(error), Err(Error::Thrown(thrown))) => {
            assert_eq!(Some(thrown.name.as_str()), error.get("name").and_then(JsValue::as_str), "{context}: class");
            assert_eq!(Some(thrown.message.as_str()), error.get("message").and_then(JsValue::as_str), "{context}");
        }
        (_, _, got) => panic!("{context}: expected {expected:?}, got {got:?}"),
    }
}

#[test]
fn the_reference_operations() {
    let vectors = vectors();
    let operations = vectors.get("operations").and_then(JsValue::as_array).unwrap();
    assert!(operations.len() > 100);
    let (_dir, mut store) = fresh();
    let mut rows = JsValue::Array(Vec::new());
    for (index, step) in operations.iter().enumerate() {
        let op = step.get("op").and_then(JsValue::as_str).unwrap();
        let args = step.get("args").and_then(JsValue::as_array).unwrap();
        let context = format!("step {index} ({op} {})", JsValue::Array(args.to_vec()).stringify());
        let got = run(&mut store, op, args, now(step));
        check_result(&context, got, step.get("result").unwrap());
        // A step that left the table unchanged records no rows.
        if let Some(after) = step.get("rows") {
            assert_ne!(after, &rows, "{context}: the vector records rows only where they changed");
            rows = after.clone();
        }
        assert_eq!(table(&store), rows, "{context}: rows");
    }
}

#[test]
fn the_reference_imports() {
    let vectors = vectors();
    let imports = vectors.get("imports").and_then(JsValue::as_array).unwrap();
    let mut replayed = 0;
    for case in imports {
        let name = case.get("name").and_then(JsValue::as_str).unwrap();
        // A `.migrated` beside the file: the import's file checks, which
        // drop the stray file before reading it (the methods' step).
        if case.get("migrated") == Some(&JsValue::Bool(true)) {
            continue;
        }
        let (_dir, mut store) = fresh();
        for entry in case.get("before").and_then(JsValue::as_array).unwrap() {
            store.append(entry, now(case)).unwrap();
        }
        let files: Vec<&str> =
            case.get("files").and_then(JsValue::as_array).unwrap().iter().filter_map(JsValue::as_str).collect();
        let imported = files == ["x402-receipts.json.migrated"];
        assert!(imported || files == ["x402-receipts.json"], "{name}: {files:?}");
        let text = case.get("text").and_then(JsValue::as_str).unwrap();
        match store.import_legacy(text, now(case)) {
            Ok(_) => assert!(imported, "{name}: imported where the reference kept the file"),
            Err(Error::Thrown(thrown)) => assert!(!imported, "{name}: refused ({thrown}) where the reference imported"),
            Err(e) => panic!("{name}: {e}"),
        }
        assert_eq!(&table(&store), case.get("rows").unwrap(), "{name}: rows");
        replayed += 1;
    }
    assert_eq!(replayed, imports.len() - 1);
}

/// A refused write changes nothing and leaves the store usable.
#[test]
fn a_refusal_writes_nothing() {
    let (_dir, mut store) = fresh();
    let entry = fc_json::parse(r#"{"kind":"x402","chainId":1,"amount":"1","txHash":true}"#).unwrap();
    assert!(matches!(store.append(&entry, 1.0), Err(Error::Thrown(_))));
    assert_eq!(table(&store), JsValue::Array(Vec::new()));
    let entry = fc_json::parse(r#"{"kind":"x402","chainId":1,"amount":"1"}"#).unwrap();
    assert!(store.append(&entry, 1.0).is_ok());
}

/// An import that throws part-way keeps none of its rows: the reference's
/// one transaction.
#[test]
fn an_import_is_one_transaction() {
    let (_dir, mut store) = fresh();
    let text = r#"[{"id":"a","amount":"1"},{"id":"b","amount":"2"},null]"#;
    assert!(matches!(store.import_legacy(text, 5.0), Err(Error::Thrown(_))));
    assert_eq!(table(&store), JsValue::Array(Vec::new()));
}
