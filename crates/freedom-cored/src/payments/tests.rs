//! `vectors/sqlite.json`'s `payments`, replayed: each of the reference's
//! operations on one database, and each legacy import's rows, through
//! [`Payments`] on a database [`crate::sqlite::open`] created. After every
//! step the table must hold what the reference's left, cell for cell, with
//! SQLite's type for each, and the step must answer what the reference
//! answered or throw what it threw. Then the transactions: a writer on a
//! second connection, let in right after a read, must find each write and
//! its read-back, and each check and its write, one transaction.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use fc_json::JsValue;
use fc_wallet_state::payments::{COLUMNS, Cell, Row};
use rusqlite::types::Value;
use rusqlite::{Connection, ErrorCode};

use super::{Error, Payments, SCHEMA};
use crate::sqlite;

type Hook = Box<dyn FnMut(&str)>;

thread_local! {
    static AFTER_READ: RefCell<Option<Hook>> = RefCell::new(None);
}

/// Called by [`super::rows`] once a statement's rows are read, inside its
/// transaction if it has one.
pub(super) fn after_read_hook(sql: &str) {
    let hook = AFTER_READ.with(|hook| hook.borrow_mut().take());
    if let Some(mut hook) = hook {
        hook(sql);
        AFTER_READ.with(|slot| *slot.borrow_mut() = Some(hook));
    }
}

fn after_read(hook: impl FnMut(&str) + 'static) {
    AFTER_READ.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sqlite.json");
    let text = std::fs::read_to_string(path).unwrap();
    fc_json::parse(&text)
        .unwrap()
        .get("payments")
        .cloned()
        .unwrap()
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
    let rows = super::rows(
        &store.conn,
        &statement("SELECT * FROM payments ORDER BY id"),
    )
    .unwrap();
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
                                Cell::Blob(bytes) => ("blob", JsValue::string(hex(bytes))),
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
    fc_wallet_state::payments::Statement {
        sql: sql.to_owned(),
        params: Vec::new(),
    }
}

/// A row as better-sqlite3's `all()` answers it: `{ column: value }`, a
/// BLOB's `Buffer` as the generator shows it, `{ blob: hex }`.
fn raw(row: &Row) -> JsValue {
    object(
        COLUMNS
            .iter()
            .zip(row)
            .map(|(column, cell)| {
                let value = match cell {
                    Cell::Blob(bytes) => object(vec![("blob", JsValue::string(hex(bytes)))]),
                    cell => cell.to_js().unwrap(),
                };
                (*column, value)
            })
            .collect(),
    )
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
        "setDroppedSeen" => store
            .set_dropped_seen(&arg(0), &arg(1), now_ms)
            .map(|_| JsValue::Null),
        "pending" => store
            .pending()
            .map(|rows| JsValue::Array(rows.iter().map(raw).collect())),
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
            assert_eq!(
                Some(thrown.name.as_str()),
                error.get("name").and_then(JsValue::as_str),
                "{context}: class"
            );
            assert_eq!(
                Some(thrown.message.as_str()),
                error.get("message").and_then(JsValue::as_str),
                "{context}"
            );
        }
        (_, _, got) => panic!("{context}: expected {expected:?}, got {got:?}"),
    }
}

#[test]
fn the_reference_operations() {
    let vectors = vectors();
    let operations = vectors
        .get("operations")
        .and_then(JsValue::as_array)
        .unwrap();
    assert!(operations.len() > 100);
    let (_dir, mut store) = fresh();
    let mut rows = JsValue::Array(Vec::new());
    for (index, step) in operations.iter().enumerate() {
        let op = step.get("op").and_then(JsValue::as_str).unwrap();
        let args = step.get("args").and_then(JsValue::as_array).unwrap();
        let context = format!(
            "step {index} ({op} {})",
            JsValue::Array(args.to_vec()).stringify()
        );
        let got = run(&mut store, op, args, now(step));
        check_result(&context, got, step.get("result").unwrap());
        // A step that left the table unchanged records no rows.
        if let Some(after) = step.get("rows") {
            assert_ne!(
                after, &rows,
                "{context}: the vector records rows only where they changed"
            );
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
        let files: Vec<&str> = case
            .get("files")
            .and_then(JsValue::as_array)
            .unwrap()
            .iter()
            .filter_map(JsValue::as_str)
            .collect();
        let imported = files == ["x402-receipts.json.migrated"];
        assert!(
            imported || files == ["x402-receipts.json"],
            "{name}: {files:?}"
        );
        let text = case.get("text").and_then(JsValue::as_str).unwrap();
        // The reference's `Date.now()` answers, in the order it asked.
        let ticks: Vec<f64> = case
            .get("ticks")
            .and_then(JsValue::as_array)
            .unwrap()
            .iter()
            .map(|tick| match tick {
                JsValue::Number(n) => *n,
                other => panic!("{name}: tick {other:?}"),
            })
            .collect();
        let mut asked = 0;
        let clock = || {
            asked += 1;
            *ticks
                .get(asked - 1)
                .unwrap_or_else(|| panic!("{name}: the clock read more often than the reference's"))
        };
        let outcome = store.import_legacy(text, clock);
        assert_eq!(asked, ticks.len(), "{name}: the clock's reads");
        match outcome {
            Ok(_) => assert!(
                imported,
                "{name}: imported where the reference kept the file"
            ),
            Err(Error::Thrown(thrown)) => assert!(
                !imported,
                "{name}: refused ({thrown}) where the reference imported"
            ),
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
    let entry =
        fc_json::parse(r#"{"kind":"x402","chainId":1,"amount":"1","txHash":true}"#).unwrap();
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
    assert!(matches!(
        store.import_legacy(text, || 5.0),
        Err(Error::Thrown(_))
    ));
    assert_eq!(table(&store), JsValue::Array(Vec::new()));
}

/// `{ blob: hex }`, the generator's `Buffer`, as a record answers it: `null`
/// (design 0013's `payments-json-values`).
fn nulled(value: &JsValue) -> JsValue {
    match value {
        JsValue::Object(props) if props.len() == 1 && props[0].0 == *"blob" => JsValue::Null,
        JsValue::Object(props) => {
            JsValue::Object(props.iter().map(|(k, v)| (k.clone(), nulled(v))).collect())
        }
        JsValue::Array(items) => JsValue::Array(items.iter().map(nulled).collect()),
        other => other.clone(),
    }
}

/// Puts `rows` (the generator's `[typeof, value]` cells) in the table as
/// they are, BLOBs included.
fn insert_cells(store: &Payments, rows: &JsValue) {
    let sql = format!(
        "INSERT INTO payments ({}) VALUES ({})",
        COLUMNS.join(", "),
        vec!["?"; COLUMNS.len()].join(", ")
    );
    for row in rows.as_array().unwrap() {
        let values: Vec<Value> = COLUMNS
            .iter()
            .map(|column| {
                let cell = row.get(column).and_then(JsValue::as_array).unwrap();
                let value = &cell[1];
                match cell[0].as_str().unwrap() {
                    "null" => Value::Null,
                    "integer" => Value::Integer(value.as_str().unwrap().parse().unwrap()),
                    "real" => match value {
                        JsValue::Number(n) => Value::Real(*n),
                        other => panic!("real {other:?}"),
                    },
                    "text" => Value::Text(value.as_str().unwrap().to_owned()),
                    "blob" => Value::Blob(unhex(value.as_str().unwrap())),
                    other => panic!("typeof {other}"),
                }
            })
            .collect();
        store
            .conn
            .execute(&sql, rusqlite::params_from_iter(values))
            .unwrap();
    }
}

/// A database the reference wrote with BLOB cells (a `Buffer` handed to
/// `append` and to `update`), read and written through the core: each
/// record answers `null` for a BLOB and the row is still listed; the
/// repoll's raw rows carry the bytes; the marks change only what the
/// reference changed, and leave the BLOBs as they were.
#[test]
fn a_reference_database_with_blobs() {
    let vectors = vectors();
    let blob = vectors.get("blob").unwrap();
    let setup = blob.get("setup").and_then(JsValue::as_array).unwrap();
    let (_dir, mut store) = fresh();
    let mut rows = setup.last().unwrap().get("rows").unwrap().clone();
    insert_cells(&store, &rows);
    assert_eq!(table(&store), rows);
    assert!(rows.stringify().contains(r#"["blob","#));
    for (index, step) in blob
        .get("steps")
        .and_then(JsValue::as_array)
        .unwrap()
        .iter()
        .enumerate()
    {
        let op = step.get("op").and_then(JsValue::as_str).unwrap();
        let args = step.get("args").and_then(JsValue::as_array).unwrap();
        let context = format!("blob step {index} ({op})");
        let got = run(&mut store, op, args, now(step));
        let result = step.get("result").unwrap();
        // The repoll's raw rows are the second part's to map.
        let expected = if op == "pending" {
            result.clone()
        } else {
            nulled(result)
        };
        check_result(&context, got, &expected);
        rows = step.get("rows").unwrap().clone();
        assert_eq!(table(&store), rows, "{context}: rows");
    }
}

/// `getRecent`'s page on a table of 501 rows the reference appended: 50
/// without a limit, at most 500 with one.
#[test]
fn the_reference_pages() {
    let vectors = vectors();
    let pages = vectors.get("pages").unwrap();
    let (_dir, mut store) = fresh();
    let JsValue::Number(count) = pages.get("count").unwrap() else {
        panic!("count")
    };
    let JsValue::Number(created_at) = pages.get("createdAt").unwrap() else {
        panic!("createdAt")
    };
    for n in 1..=u32::try_from(*count as i64).unwrap() {
        let mut entry = pages.get("entry").unwrap().clone();
        entry.set("createdAt", JsValue::Number(created_at + f64::from(n)));
        store.append(&entry, 0.0).unwrap();
    }
    for page in pages.get("pages").and_then(JsValue::as_array).unwrap() {
        let filters = page.get("filters").unwrap();
        let filters = if filters == &JsValue::Null {
            JsValue::Undefined
        } else {
            filters.clone()
        };
        let found = store.get_recent(&filters).unwrap();
        let ids: Vec<&JsValue> = found.iter().map(|entry| entry.get("id").unwrap()).collect();
        let context = filters.stringify();
        assert_eq!(&number(ids.len()), page.get("length").unwrap(), "{context}");
        for (index, id) in ids.iter().enumerate() {
            let JsValue::Number(first) = page.get("first").unwrap() else {
                panic!("first")
            };
            assert_eq!(
                **id,
                JsValue::Number(first - f64::from(u32::try_from(index).unwrap())),
                "{context}"
            );
        }
        assert_eq!(
            ids.last().copied().unwrap_or(&JsValue::Null),
            page.get("last").unwrap(),
            "{context}"
        );
    }
    assert_eq!(
        &store.get_count(&JsValue::Undefined).unwrap(),
        pages.get("total").unwrap()
    );
}

fn second(dir: &Path) -> Connection {
    let conn = Connection::open(dir.join("payment-history.sqlite")).unwrap();
    conn.busy_timeout(Duration::ZERO).unwrap();
    conn
}

fn busy(outcome: &rusqlite::Result<usize>) -> bool {
    matches!(outcome, Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::DatabaseBusy)
}

/// After each read of `sql` (the first `times`), a writer on a second
/// connection runs `write`; the outcomes, in order.
fn writer_after(
    dir: &Path,
    sql: &'static str,
    write: &'static str,
) -> Rc<RefCell<Vec<rusqlite::Result<usize>>>> {
    let other = second(dir);
    let outcomes = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&outcomes);
    after_read(move |read| {
        if read == sql {
            seen.borrow_mut().push(other.execute(write, []));
        }
    });
    outcomes
}

fn status(store: &Payments, id: i64) -> String {
    store
        .conn
        .query_row("SELECT status FROM payments WHERE id = ?", [id], |row| {
            row.get(0)
        })
        .unwrap()
}

const FINALIZE: &str = "UPDATE payments SET status = 'confirmed' WHERE id = 1";

/// A write and its read-back are one transaction: a writer let in after
/// the read-back's read can't commit until the write has, so the answer is
/// the row the write left (append's and update's).
#[test]
fn a_write_and_its_read_back_are_one_transaction() {
    let (dir, mut store) = fresh();
    let outcomes = writer_after(dir.path(), fc_wallet_state::payments::BY_ID_SQL, FINALIZE);
    let entry = fc_json::parse(r#"{"kind":"wallet-send","chainId":1,"amount":"1"}"#).unwrap();
    let appended = store.append(&entry, 1.0).unwrap();
    assert_eq!(appended.get("status"), Some(&JsValue::string("pending")));
    let patch = fc_json::parse(r#"{"gasPrice":"5"}"#).unwrap();
    let updated = store.update(&JsValue::Number(1.0), &patch, 2.0).unwrap();
    assert_eq!(updated.get("status"), Some(&JsValue::string("pending")));
    assert_eq!(updated.get("gasPrice"), Some(&JsValue::string("5")));
    let outcomes = outcomes.borrow();
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.iter().all(busy), "{outcomes:?}");
    // Once committed, the other writer gets in.
    assert_eq!(second(dir.path()).execute(FINALIZE, []).unwrap(), 1);
    assert_eq!(status(&store, 1), "confirmed");
}

/// A finalizer can't commit between `mark_dropped`'s (and the repoll's
/// write's) check that the row is pending and its write, so a row it
/// finalized is never overwritten as dropped: the transaction is
/// immediate, holding the write lock from its start. (A deferred one lets
/// the finalizer commit after the check's read, and its own write then
/// fails `SQLITE_BUSY_SNAPSHOT`.)
#[test]
fn a_finalizer_cannot_commit_inside_a_check_and_its_write() {
    let entry = fc_json::parse(r#"{"kind":"wallet-send","chainId":1,"amount":"1"}"#).unwrap();
    for mark in ["markDropped", "setDroppedSeen"] {
        let (dir, mut store) = fresh();
        store.append(&entry, 1.0).unwrap();
        let outcomes = writer_after(dir.path(), fc_wallet_state::payments::BY_ID_SQL, FINALIZE);
        let id = JsValue::Number(1.0);
        let marked = match mark {
            "markDropped" => store.mark_dropped(&id, 2.0),
            _ => store.set_dropped_seen(&id, &JsValue::Number(2.0), 2.0),
        }
        .unwrap();
        let expected = if mark == "markDropped" {
            "dropped"
        } else {
            "pending"
        };
        assert_eq!(
            marked.get("status"),
            Some(&JsValue::string(expected)),
            "{mark}"
        );
        let held_off = outcomes.borrow().iter().all(busy);
        assert!(held_off, "{mark}: {:?}", outcomes.borrow());
        // The finalizer, retried once the mark committed, lands; had it
        // landed inside, the mark would have overwritten it.
        if held_off {
            assert_eq!(second(dir.path()).execute(FINALIZE, []).unwrap(), 1);
        }
        assert_eq!(status(&store, 1), "confirmed", "{mark}");
    }
}
