//! `payments.*`' store: the import's file steps at the first open, the
//! answers on the wire, the handover and the failure paths. The rows after
//! each of the reference's operations are `payments::tests`'.

use std::path::{Path, PathBuf};

use fc_json::JsValue;
use fc_protocol::error::{ErrorBody, ErrorCode};
use rusqlite::types::ValueRef;

use super::{DB_FILE, LEGACY_FILE, Legacy, MAX_LEGACY_BYTES, MIGRATED_FILE, Store};
use crate::payments::{Payments, SCHEMA};
use crate::sqlite;

fn vectors() -> JsValue {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sqlite.json");
    let text = std::fs::read_to_string(path).unwrap();
    fc_json::parse(&text)
        .unwrap()
        .get("payments")
        .cloned()
        .unwrap()
}

fn now(step: &JsValue) -> f64 {
    match step.get("now") {
        Some(JsValue::Number(n)) => *n,
        other => panic!("now: {other:?}"),
    }
}

fn open(root: &Path) -> Payments {
    Payments::new(sqlite::open(&root.join(DB_FILE), &SCHEMA).unwrap())
}

/// The table under `root` as the generator reads it, through a connection
/// of its own: each column `[typeof, value]`, an INTEGER as its decimal
/// text.
fn table_at(root: &Path) -> JsValue {
    let conn = rusqlite::Connection::open(root.join(DB_FILE)).unwrap();
    let mut select = conn.prepare("SELECT * FROM payments ORDER BY id").unwrap();
    let names: Vec<String> = select.column_names().map(str::to_owned).collect();
    let mut rows = select.query([]).unwrap();
    let mut out = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        let mut props = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let (kind, value) = match row.get_ref(index).unwrap() {
                ValueRef::Null => ("null", JsValue::Null),
                ValueRef::Integer(n) => ("integer", JsValue::string(n.to_string())),
                ValueRef::Real(n) => ("real", JsValue::Number(n)),
                ValueRef::Text(text) => {
                    ("text", JsValue::string(std::str::from_utf8(text).unwrap()))
                }
                ValueRef::Blob(_) => panic!("a blob"),
            };
            props.push((
                name.as_str().into(),
                JsValue::Array(vec![JsValue::string(kind), value]),
            ));
        }
        out.push(JsValue::Object(props));
    }
    JsValue::Array(out)
}

const T: u64 = 1_700_000_000_000;

fn named(root: &Path) -> Store {
    let mut store = Store::new();
    store.configure(root.to_path_buf());
    store
}

/// A request's answer as `fc_json` reads it, or its error.
fn call(store: &mut Store, method: &str, params: &str) -> Result<JsValue, ErrorBody> {
    store
        .request(method, Some(params), T)
        .map(|raw| fc_json::parse(raw.get()).unwrap())
}

/// The files beside the database, as the generator lists them.
fn files(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with(DB_FILE))
        .collect();
    names.sort();
    names
}

fn storage_kind(error: &ErrorBody) -> &str {
    assert_eq!(error.code, ErrorCode::Storage, "{error:?}");
    let data = error.data.as_ref().unwrap();
    assert_eq!(data["store"], "payments");
    data["kind"].as_str().unwrap()
}

/// Every import vector through the methods' first open: the rows, and the
/// files left (the stray file dropped beside a `.migrated`, the file renamed
/// after a whole import, kept after a refusal), as the reference left them.
#[test]
fn the_reference_imports_with_their_files() {
    let vectors = vectors();
    let imports = vectors.get("imports").and_then(JsValue::as_array).unwrap();
    for case in imports {
        let name = case.get("name").and_then(JsValue::as_str).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let before = case.get("before").and_then(JsValue::as_array).unwrap();
        if !before.is_empty() {
            let mut first = open(root);
            for entry in before {
                first.append(entry, now(case)).unwrap();
            }
        }
        let text = case.get("text").and_then(JsValue::as_str).unwrap();
        std::fs::write(root.join(LEGACY_FILE), text).unwrap();
        if case.get("migrated") == Some(&JsValue::Bool(true)) {
            std::fs::write(root.join(MIGRATED_FILE), "[]").unwrap();
        }
        let mut store = named(root);
        call(&mut store, "payments.get_count", "{}").unwrap();
        assert_eq!(&table_at(root), case.get("rows").unwrap(), "{name}: rows");
        let expected: Vec<&str> = case
            .get("files")
            .and_then(JsValue::as_array)
            .unwrap()
            .iter()
            .filter_map(JsValue::as_str)
            .collect();
        assert_eq!(files(root), expected, "{name}: files");
        // Once per open: a file put back later waits for the next start.
        std::fs::write(root.join(LEGACY_FILE), text).unwrap();
        call(&mut store, "payments.get_count", "{}").unwrap();
        assert!(root.join(LEGACY_FILE).exists(), "{name}");
        assert_eq!(&table_at(root), case.get("rows").unwrap(), "{name}: again");
    }
}

/// Rows committed but the file not renamed (a crash between): the next
/// first open finds every row there, imports none, and renames the file.
#[test]
fn an_import_cut_before_its_rename_is_finished_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let text = r#"[{"id":"r1","settledAt":1699000000,"status":"settled","chainId":8453,"amount":"500","origin":"https://x.example","url":"https://x.example/a"}]"#;
    std::fs::write(root.join(LEGACY_FILE), text).unwrap();
    let mut payments = open(root);
    assert_eq!(payments.import_legacy(text, || 1.0).unwrap(), 1);
    let rows = table_at(root);
    assert_eq!(
        Store::import(root, &mut payments, 2.0),
        Legacy::Imported(0, true)
    );
    assert_eq!(table_at(root), rows);
    assert_eq!(files(root), [MIGRATED_FILE]);
    // Then the file is gone: nothing more to do.
    assert_eq!(Store::import(root, &mut payments, 3.0), Legacy::Absent);
    // A stray file beside the `.migrated` is dropped, unread.
    std::fs::write(root.join(LEGACY_FILE), "not json").unwrap();
    assert_eq!(Store::import(root, &mut payments, 4.0), Legacy::Stray(true));
    assert_eq!(files(root), [MIGRATED_FILE]);
    assert_eq!(table_at(root), rows);
}

/// A file past the bound, or not a regular file, is left in place unread,
/// and the database serves without it.
#[test]
fn an_unreadable_legacy_file_is_left() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let mut text = String::from("[");
    text.push_str(&" ".repeat(MAX_LEGACY_BYTES - 2));
    text.push(']');
    assert_eq!(text.len(), MAX_LEGACY_BYTES);
    std::fs::write(root.join(LEGACY_FILE), format!("{text} ")).unwrap();
    let mut payments = open(root);
    assert_eq!(Store::import(root, &mut payments, 1.0), Legacy::Kept);
    assert_eq!(files(root), [LEGACY_FILE]);
    // At the bound, it is read (and, an empty array, renamed).
    std::fs::write(root.join(LEGACY_FILE), &text).unwrap();
    assert_eq!(
        Store::import(root, &mut payments, 1.0),
        Legacy::Imported(0, true)
    );
    assert_eq!(files(root), [MIGRATED_FILE]);
    #[cfg(unix)]
    {
        std::fs::remove_file(root.join(MIGRATED_FILE)).unwrap();
        std::fs::write(root.join("elsewhere.json"), "[]").unwrap();
        std::os::unix::fs::symlink("elsewhere.json", root.join(LEGACY_FILE)).unwrap();
        assert_eq!(Store::import(root, &mut payments, 1.0), Legacy::Kept);
        assert!(root.join(LEGACY_FILE).is_symlink());
        assert!(!root.join(MIGRATED_FILE).exists());
    }
}

/// The methods' answers on the wire.
#[test]
fn the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = named(dir.path());
    let first = call(
        &mut store,
        "payments.append",
        r#"{"entry":{"kind":"wallet-send","chainId":1,"amount":"5","txHash":"0xaa","createdAt":10,"metadata":{"txNonce":3,"lone":"\ud800"}}}"#,
    )
    .unwrap();
    let payment = first.get("payment").unwrap();
    assert_eq!(payment.get("id"), Some(&JsValue::Number(1.0)));
    assert_eq!(
        payment.get("status").and_then(JsValue::as_str),
        Some("pending")
    );
    assert_eq!(
        payment.get("metadata").map(JsValue::stringify).as_deref(),
        Some(r#"{"txNonce":3,"lone":"\ud800"}"#)
    );
    let refused = call(
        &mut store,
        "payments.append",
        r#"{"entry":{"kind":"nope"}}"#,
    )
    .unwrap_err();
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert_eq!(refused.message, "payment-history: unknown kind 'nope'");
    assert_eq!(refused.data, Some(serde_json::json!({ "name": "Error" })));
    let refused = call(
        &mut store,
        "payments.mark_failed",
        r#"{"id":1,"info":null}"#,
    )
    .unwrap_err();
    assert_eq!(
        refused.data,
        Some(serde_json::json!({ "name": "TypeError" }))
    );
    // The repoll: its rows as it reads them (snake_case, metadata as its
    // text), its sighting written while pending, answering nothing.
    let pending = call(&mut store, "payments.pending", "{}").unwrap();
    let rows = pending.get("payments").and_then(JsValue::as_array).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("tx_hash").and_then(JsValue::as_str),
        Some("0xaa")
    );
    assert_eq!(rows[0].get("chain_id"), Some(&JsValue::Number(1.0)));
    assert_eq!(rows[0].get("created_at"), Some(&JsValue::Number(10.0)));
    assert_eq!(
        rows[0].get("metadata").and_then(JsValue::as_str),
        Some(r#"{"txNonce":3,"lone":"\ud800"}"#)
    );
    let seen = store
        .request(
            "payments.set_dropped_seen",
            Some(r#"{"id":1,"seen_at":99}"#),
            T,
        )
        .unwrap();
    assert_eq!(seen.get(), "{}");
    let after = call(&mut store, "payments.pending", "{}").unwrap();
    let after = after.get("payments").and_then(JsValue::as_array).unwrap();
    assert_eq!(
        after[0].get("metadata").and_then(JsValue::as_str),
        Some(r#"{"txNonce":3,"lone":"\ud800","txDroppedSeenAt":99}"#)
    );
    let confirmed = call(
        &mut store,
        "payments.mark_confirmed",
        r#"{"id":1,"receipt":{"gasUsed":"21000"}}"#,
    )
    .unwrap();
    assert_eq!(
        confirmed
            .get("payment")
            .and_then(|p| p.get("status"))
            .and_then(JsValue::as_str),
        Some("confirmed")
    );
    // No longer pending: neither the sighting nor the drop writes.
    let unchanged = store
        .request(
            "payments.set_dropped_seen",
            Some(r#"{"id":1,"seen_at":null}"#),
            T,
        )
        .unwrap();
    assert_eq!(unchanged.get(), "{}");
    let pending = call(&mut store, "payments.pending", "{}").unwrap();
    assert_eq!(pending.get("payments"), Some(&JsValue::Array(Vec::new())));
    for (method, params) in [
        ("payments.mark_dropped", r#"{"id":1}"#),
        ("payments.update", r#"{"id":7,"patch":{"status":"failed"}}"#),
        ("payments.get_by_id", r#"{"id":2}"#),
    ] {
        let answer = call(&mut store, method, params).unwrap();
        assert_eq!(answer.get("payment"), Some(&JsValue::Null), "{method}");
    }
    let count = call(
        &mut store,
        "payments.get_count",
        r#"{"filters":{"status":"confirmed"}}"#,
    )
    .unwrap();
    assert_eq!(count.get("count"), Some(&JsValue::Number(1.0)));
    let recent = call(&mut store, "payments.get_recent", "{}").unwrap();
    assert_eq!(
        recent
            .get("payments")
            .and_then(JsValue::as_array)
            .map(<[_]>::len),
        Some(1)
    );
    let cleared = call(&mut store, "payments.clear", "{}").unwrap();
    assert_eq!(cleared.get("removed"), Some(&JsValue::Number(1.0)));
    let cleared = store.request("payments.clear", None, T).unwrap();
    assert_eq!(cleared.get(), r#"{"removed":0}"#);
    for params in ["[]", "1", "null", "not json"] {
        let refused = call(&mut store, "payments.get_count", params).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidArgument, "{params}");
    }
    let unknown = call(&mut store, "payments.remove_by_id", "{}").unwrap_err();
    assert_eq!(unknown.code, ErrorCode::UnknownMethod);
}

/// Not named: every method `not_moved`, and nothing opened or created.
#[test]
fn not_named_opens_nothing() {
    let mut store = Store::new();
    for method in super::METHODS {
        let refused = store.request(method, Some("{}"), T).unwrap_err();
        assert_eq!(refused.code, ErrorCode::NotMoved, "{method}");
        assert_eq!(
            refused.data,
            Some(serde_json::json!({ "store": "payments" }))
        );
    }
    assert!(store.open.is_none());
}

/// Another connection holding the write lock: a write answers `storage`
/// (`busy`) after the busy timeout, with nothing written, while reads still
/// serve; once released, the write goes through. A write SQLite refuses
/// answers `storage` (`io`), with nothing written.
#[test]
fn busy_and_failed_writes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let mut store = named(root);
    let append = r#"{"entry":{"kind":"x402","chainId":1,"amount":"1","createdAt":5}}"#;
    call(&mut store, "payments.append", append).unwrap();
    let other = rusqlite::Connection::open(root.join(DB_FILE)).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = std::time::Instant::now();
    let busy = call(&mut store, "payments.append", append).unwrap_err();
    assert_eq!(storage_kind(&busy), "busy");
    assert!(started.elapsed() >= sqlite::BUSY_TIMEOUT);
    let busy = call(&mut store, "payments.clear", "{}").unwrap_err();
    assert_eq!(storage_kind(&busy), "busy");
    let count = call(&mut store, "payments.get_count", "{}").unwrap();
    assert_eq!(count.get("count"), Some(&JsValue::Number(1.0)));
    other.execute_batch("ROLLBACK").unwrap();
    call(&mut store, "payments.append", append).unwrap();
    // A refused write: the store's connection made read-only.
    let conn = sqlite::open(&root.join(DB_FILE), &SCHEMA).unwrap();
    conn.pragma_update(None, "query_only", true).unwrap();
    store.open = Some(Payments::new(conn));
    let failed = call(&mut store, "payments.append", append).unwrap_err();
    assert_eq!(storage_kind(&failed), "io");
    let failed = call(&mut store, "payments.mark_dropped", r#"{"id":1}"#).unwrap_err();
    assert_eq!(storage_kind(&failed), "io");
    let count = call(&mut store, "payments.get_count", "{}").unwrap();
    assert_eq!(count.get("count"), Some(&JsValue::Number(2.0)));
}

/// An open that fails (another schema's database) answers `storage`
/// (`unreadable`), changes nothing, imports nothing, and is tried again at
/// the next request.
#[test]
fn a_failed_open_is_tried_again() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    {
        let conn = rusqlite::Connection::open(root.join(DB_FILE)).unwrap();
        conn.execute_batch("PRAGMA user_version = 7").unwrap();
    }
    let bytes = std::fs::read(root.join(DB_FILE)).unwrap();
    std::fs::write(root.join(LEGACY_FILE), "[]").unwrap();
    let mut store = named(root);
    let refused = call(&mut store, "payments.get_recent", "{}").unwrap_err();
    assert_eq!(storage_kind(&refused), "unreadable");
    assert_eq!(std::fs::read(root.join(DB_FILE)).unwrap(), bytes);
    assert_eq!(files(root), [LEGACY_FILE]);
    std::fs::remove_file(root.join(DB_FILE)).unwrap();
    let recent = call(&mut store, "payments.get_recent", "{}").unwrap();
    assert_eq!(recent.get("payments"), Some(&JsValue::Array(Vec::new())));
    assert_eq!(files(root), [MIGRATED_FILE]);
}
