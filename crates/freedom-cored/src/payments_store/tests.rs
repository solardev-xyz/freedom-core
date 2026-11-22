//! `payments.*`' store: the import's file steps at the first open, the
//! answers on the wire, the handover and the failure paths. The rows after
//! each of the reference's operations are `payments::tests`'.

use std::path::{Path, PathBuf};
use std::time::Duration;

use fc_json::JsValue;
use fc_protocol::error::{ErrorBody, ErrorCode};
use rusqlite::types::ValueRef;

use fc_store::fsx::Done;
use fc_store::{Hooks, NoHooks, Step};

use super::{
    DB_FILE, Handover, Import, LEGACY_FILE, Legacy, MAX_LEGACY_BYTES, MIGRATED_FILE, Store,
    hand_over,
};
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
    store.configure(root.to_path_buf(), Import::at(root.to_path_buf()));
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
/// after a whole import, kept after a refusal), as the reference left them,
/// with its `Date.now()` answers replayed per entry.
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
        let mut store = named(root);
        // What the first request runs, with the replayed clock.
        Store::opened(store.roots.as_ref().unwrap(), &mut store.open, clock).unwrap();
        assert_eq!(asked, ticks.len(), "{name}: the clock's reads");
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
        Store::import(root, &mut payments, || 2.0),
        Legacy::Imported(0, true)
    );
    assert_eq!(table_at(root), rows);
    assert_eq!(files(root), [MIGRATED_FILE]);
    // Then the file is gone: nothing more to do.
    assert_eq!(Store::import(root, &mut payments, || 3.0), Legacy::Absent);
    // A stray file beside the `.migrated` is dropped, unread.
    std::fs::write(root.join(LEGACY_FILE), "not json").unwrap();
    assert_eq!(
        Store::import(root, &mut payments, || 4.0),
        Legacy::Stray(true)
    );
    assert_eq!(files(root), [MIGRATED_FILE]);
    assert_eq!(table_at(root), rows);
}

/// The database under one root and `x402-receipts.json` under another
/// (the hello's `grant_root` and `user_data_dir`, PRF-8-lite): the first
/// open imports the receipts from the import root and renames them there,
/// and leaves a file at the database's root unread and in place.
#[test]
fn the_import_reads_its_own_root() {
    let db_dir = tempfile::tempdir().unwrap();
    let import_dir = tempfile::tempdir().unwrap();
    let (db_root, import_root) = (db_dir.path(), import_dir.path());
    let receipt = |id: &str| {
        format!(
            r#"[{{"id":"{id}","settledAt":1699000000,"status":"settled","chainId":8453,"amount":"500","origin":"https://x.example","url":"https://x.example/a"}}]"#
        )
    };
    std::fs::write(import_root.join(LEGACY_FILE), receipt("there")).unwrap();
    std::fs::write(db_root.join(LEGACY_FILE), receipt("beside")).unwrap();
    let mut store = Store::new();
    store.configure(db_root.to_path_buf(), Import::at(import_root.to_path_buf()));
    let recent = call(&mut store, "payments.get_recent", "{}").unwrap();
    let recent = recent.get("payments").and_then(JsValue::as_array).unwrap();
    assert_eq!(recent.len(), 1);
    let legacy_id = recent[0]
        .get("metadata")
        .and_then(|metadata| metadata.get("legacyId"))
        .and_then(JsValue::as_str);
    assert_eq!(legacy_id, Some("there"));
    assert!(db_root.join(DB_FILE).exists());
    assert!(!import_root.join(DB_FILE).exists());
    assert_eq!(files(import_root), [MIGRATED_FILE]);
    assert_eq!(files(db_root), [LEGACY_FILE]);
    assert_eq!(
        std::fs::read_to_string(db_root.join(LEGACY_FILE)).unwrap(),
        receipt("beside")
    );
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
    assert_eq!(Store::import(root, &mut payments, || 1.0), Legacy::Kept);
    assert_eq!(files(root), [LEGACY_FILE]);
    // At the bound, it is read (and, an empty array, renamed).
    std::fs::write(root.join(LEGACY_FILE), &text).unwrap();
    assert_eq!(
        Store::import(root, &mut payments, || 1.0),
        Legacy::Imported(0, true)
    );
    assert_eq!(files(root), [MIGRATED_FILE]);
    #[cfg(unix)]
    {
        std::fs::remove_file(root.join(MIGRATED_FILE)).unwrap();
        std::fs::write(root.join("elsewhere.json"), "[]").unwrap();
        std::os::unix::fs::symlink("elsewhere.json", root.join(LEGACY_FILE)).unwrap();
        assert_eq!(Store::import(root, &mut payments, || 1.0), Legacy::Kept);
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
    // An update of the row: its patch's fields written, the rest kept.
    let updated = call(
        &mut store,
        "payments.update",
        r#"{"id":1,"patch":{"txHash":"0xbb","gasPrice":"7"}}"#,
    )
    .unwrap();
    let updated = updated.get("payment").unwrap();
    for (field, value) in [
        ("txHash", "0xbb"),
        ("gasPrice", "7"),
        ("gasUsed", "21000"),
        ("status", "confirmed"),
    ] {
        assert_eq!(
            updated.get(field).and_then(JsValue::as_str),
            Some(value),
            "{field}"
        );
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
/// (`busy`) after the busy timeout, 500 ms (deviation
/// `sqlite-busy-timeout`, pinned apart from the constant: waited, and well
/// short of better-sqlite3's 5 s), with nothing written, while reads still
/// serve; once released, the write goes through. A write SQLite refuses
/// answers `storage` (`io`), with nothing written.
#[test]
fn busy_and_failed_writes() {
    assert_eq!(sqlite::BUSY_TIMEOUT, Duration::from_millis(500));
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
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(500), "{waited:?}");
    assert!(waited < Duration::from_secs(2), "{waited:?}");
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

/// Every name under `root`, the database's own files among them.
fn all_files(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

const RECEIPTS: &str =
    r#"[{"id":"r1","settledAt":1699000000,"status":"settled","chainId":8453,"amount":"500"}]"#;

/// A request the reference function refuses before its first `getDb()`, as
/// the first request: no database created, `x402-receipts.json` in place
/// and not renamed, nothing opened. The next request opens and imports. A
/// value only the binder refuses comes after the open (and the import), as
/// in the reference, which prepares its statement before it binds.
#[test]
fn a_refusal_before_the_first_open_opens_nothing() {
    let fresh = || {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_FILE), RECEIPTS).unwrap();
        let store = named(dir.path());
        (dir, store)
    };
    let imported = |store: &mut Store, root: &Path, context: &str| {
        let count = call(store, "payments.get_count", "{}").unwrap();
        assert_eq!(count.get("count"), Some(&JsValue::Number(1.0)), "{context}");
        assert_eq!(files(root), [MIGRATED_FILE], "{context}");
    };
    for (method, params, name) in [
        ("payments.append", "{}", "Error"),
        ("payments.append", r#"{"entry":null}"#, "TypeError"),
        ("payments.append", r#"{"entry":{"kind":"nope"}}"#, "Error"),
        (
            "payments.append",
            r#"{"entry":{"kind":"x402","chainId":"1","amount":"1"}}"#,
            "Error",
        ),
        (
            "payments.append",
            r#"{"entry":{"kind":"x402","chainId":1,"amount":"0x1"}}"#,
            "Error",
        ),
        ("payments.update", r#"{"id":1,"patch":null}"#, "TypeError"),
        (
            "payments.mark_confirmed",
            r#"{"id":1,"receipt":null}"#,
            "TypeError",
        ),
        (
            "payments.mark_failed",
            r#"{"id":1,"info":null}"#,
            "TypeError",
        ),
        ("payments.get_recent", r#"{"filters":null}"#, "TypeError"),
        ("payments.get_count", r#"{"filters":null}"#, "TypeError"),
    ] {
        let context = format!("{method} {params}");
        let (dir, mut store) = fresh();
        let root = dir.path();
        let refused = call(&mut store, method, params).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidArgument, "{context}");
        assert_eq!(
            refused.data,
            Some(serde_json::json!({ "name": name })),
            "{context}"
        );
        assert!(store.open.is_none(), "{context}");
        assert_eq!(all_files(root), [LEGACY_FILE], "{context}");
        imported(&mut store, root, &context);
    }
    for (method, params) in [
        (
            "payments.append",
            r#"{"entry":{"kind":"x402","chainId":1,"amount":"1","txHash":true}}"#,
        ),
        ("payments.update", r#"{"id":true,"patch":{}}"#),
        (
            "payments.mark_confirmed",
            r#"{"id":1,"receipt":{"gasUsed":true}}"#,
        ),
        ("payments.mark_dropped", r#"{"id":true}"#),
        ("payments.get_by_id", r#"{"id":true}"#),
        ("payments.get_count", r#"{"filters":{"kind":true}}"#),
    ] {
        let context = format!("{method} {params}");
        let (dir, mut store) = fresh();
        let root = dir.path();
        let refused = call(&mut store, method, params).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidArgument, "{context}");
        assert_eq!(
            refused.message, "SQLite3 can only bind numbers, strings, bigints, buffers, and null",
            "{context}"
        );
        assert!(store.open.is_some(), "{context}");
        assert_eq!(files(root), [MIGRATED_FILE], "{context}");
        imported(&mut store, root, &context);
    }
}

/// The import's two existence checks as `fs.existsSync` makes them, a link
/// followed: a dangling `.migrated` isn't one, so the file is imported, the
/// rename replacing the link; a `.migrated` linked to a file is one, so the
/// file is a stray; a dangling `x402-receipts.json` isn't there, beside a
/// `.migrated` or not, and is left.
#[cfg(unix)]
#[test]
fn the_import_finds_its_files_as_exists_sync_does() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join(LEGACY_FILE), RECEIPTS).unwrap();
    symlink("gone", root.join(MIGRATED_FILE)).unwrap();
    let mut payments = open(root);
    assert_eq!(
        Store::import(root, &mut payments, || 1.0),
        Legacy::Imported(1, true)
    );
    assert_eq!(files(root), [MIGRATED_FILE]);
    assert!(!root.join(MIGRATED_FILE).is_symlink());
    assert_eq!(
        std::fs::read_to_string(root.join(MIGRATED_FILE)).unwrap(),
        RECEIPTS
    );

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join(LEGACY_FILE), RECEIPTS).unwrap();
    std::fs::write(root.join("marker"), "").unwrap();
    symlink("marker", root.join(MIGRATED_FILE)).unwrap();
    let mut payments = open(root);
    assert_eq!(
        Store::import(root, &mut payments, || 1.0),
        Legacy::Stray(true)
    );
    assert_eq!(files(root), ["marker", MIGRATED_FILE]);
    assert_eq!(table_at(root), JsValue::Array(Vec::new()));

    std::fs::remove_file(root.join(MIGRATED_FILE)).unwrap();
    symlink("gone", root.join(LEGACY_FILE)).unwrap();
    assert_eq!(Store::import(root, &mut payments, || 1.0), Legacy::Absent);
    std::fs::write(root.join(MIGRATED_FILE), "").unwrap();
    assert_eq!(Store::import(root, &mut payments, || 1.0), Legacy::Absent);
    assert!(root.join(LEGACY_FILE).is_symlink());
    assert_eq!(files(root), ["marker", LEGACY_FILE, MIGRATED_FILE]);
}

/// A pending row the reference wrote with a BLOB cell (its caller handed it
/// a `Buffer`; `sqlite.json`'s `blob`), read through `payments.pending`:
/// listed, the cell answered as `null` (0013's `payments-json-values`).
#[test]
fn a_reference_blob_answers_null_in_pending() {
    let vectors = vectors();
    let blob = vectors.get("blob").unwrap();
    let setup = blob.get("setup").and_then(JsValue::as_array).unwrap();
    let rows = setup.last().unwrap().get("rows").unwrap();
    let step = blob
        .get("steps")
        .and_then(JsValue::as_array)
        .unwrap()
        .iter()
        .find(|step| step.get("op").and_then(JsValue::as_str) == Some("pending"))
        .unwrap();
    let expected = crate::payments::tests::nulled(step.get("result").unwrap().get("ok").unwrap());
    assert!(expected.stringify().contains(r#""tx_hash":null"#));
    let dir = tempfile::tempdir().unwrap();
    let mut store = named(dir.path());
    call(&mut store, "payments.get_count", "{}").unwrap();
    crate::payments::tests::insert_cells(store.open.as_ref().unwrap(), rows);
    let pending = call(&mut store, "payments.pending", "{}").unwrap();
    assert_eq!(pending.get("payments"), Some(&expected));
}

/// A damaged database answers `storage` (`unreadable`), not `io`: a file
/// that isn't a database (SQLite's `NotADatabase`, at the open), and one
/// whose pages past the first are damaged (`DatabaseCorrupt`, at the first
/// read).
#[test]
fn a_damaged_database_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join(DB_FILE), vec![0x5a; 8192]).unwrap();
    let mut store = named(root);
    let refused = call(&mut store, "payments.get_count", "{}").unwrap_err();
    assert_eq!(storage_kind(&refused), "unreadable");
    std::fs::remove_file(root.join(DB_FILE)).unwrap();
    call(
        &mut store,
        "payments.append",
        r#"{"entry":{"kind":"x402","chainId":1,"amount":"1","createdAt":5}}"#,
    )
    .unwrap();
    // Closed, so its pages are in the file.
    drop(store);
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(root.join(format!("{DB_FILE}{suffix}")));
    }
    let mut bytes = std::fs::read(root.join(DB_FILE)).unwrap();
    assert!(bytes.len() > 4096);
    bytes[4096..].fill(0xff);
    std::fs::write(root.join(DB_FILE), bytes).unwrap();
    let mut store = named(root);
    let refused = call(&mut store, "payments.get_count", "{}").unwrap_err();
    assert_eq!(storage_kind(&refused), "unreadable");
}

// Design 0017, C5: a moved profile's receipts, handed over from its root to
// the Freedom root as a copy, and imported there.

/// Two receipts, so "each row once" counts more than one.
const TWO_RECEIPTS: &str = r#"[{"id":"r1","settledAt":1699000000,"status":"settled","chainId":8453,"amount":"500"},{"id":"r2","settledAt":1699000100,"status":"settled","chainId":8453,"amount":"700"}]"#;

/// A moved profile: its root (`user_data_dir`) and its Freedom root
/// (`grant_root`) under it, as main lays them out after PRF-9.
struct Moved {
    _dir: tempfile::TempDir,
    profile: PathBuf,
    freedom: PathBuf,
}

/// The steps a write or the hand-over's sync fail at.
struct Failing(&'static [Step]);

impl Hooks for Failing {
    fn fails(&self, step: Step) -> bool {
        self.0.contains(&step)
    }
}

fn moved() -> Moved {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().to_path_buf();
    let freedom = profile.join("freedom");
    std::fs::create_dir(&freedom).unwrap();
    Moved {
        _dir: dir,
        profile,
        freedom,
    }
}

fn count(store: &mut Store) -> f64 {
    match call(store, "payments.get_count", "{}")
        .unwrap()
        .get("count")
    {
        Some(JsValue::Number(n)) => *n,
        other => panic!("count: {other:?}"),
    }
}

impl Moved {
    /// One start as `serve` makes it: the hand-over (`hooks` failing its
    /// steps), the store configured as the hello configures it, and its
    /// first request, which opens the database and runs the import. The
    /// hand-over's outcome and the store.
    fn start_store(&self, hooks: &dyn Hooks) -> (Handover, Store) {
        let handover = hand_over(&self.profile, &self.freedom, hooks);
        let mut store = Store::new();
        store.configure(
            self.freedom.clone(),
            handover.import(&self.profile, &self.freedom),
        );
        (handover, store)
    }

    /// [`Moved::start_store`]: the outcome and the rows counted by its
    /// first request.
    fn start_with(&self, hooks: &dyn Hooks) -> (Handover, f64) {
        let (handover, mut store) = self.start_store(hooks);
        (handover, count(&mut store))
    }

    fn start(&self) -> (Handover, f64) {
        self.start_with(&NoHooks)
    }

    /// The names at the profile's root, the Freedom root's own left out.
    fn profile_files(&self) -> Vec<String> {
        files(&self.profile)
            .into_iter()
            .filter(|name| name != "freedom")
            .collect()
    }

    /// The names in the Freedom root but the database's, temps included.
    fn freedom_files(&self) -> Vec<String> {
        files(&self.freedom)
    }

    fn original(&self) -> PathBuf {
        self.profile.join(LEGACY_FILE)
    }
}

const NONE: [&str; 0] = [];

/// What a case makes at a path, or in a directory.
type Make = Box<dyn Fn(&Path)>;

/// Steps 7, 4 and 1 in turn: the first start copies the root's file into
/// the Freedom root (mode 0600 on Unix), imports the copy and renames it
/// `.migrated` there, leaving the original; the next drops the original;
/// the one after finds nothing. Each row once.
#[test]
fn a_moved_profile_imports_its_copy_and_drops_the_original_next() {
    let m = moved();
    std::fs::write(m.original(), TWO_RECEIPTS).unwrap();
    assert_eq!(m.start(), (Handover::Copied(Done::Durable), 2.0));
    assert_eq!(m.profile_files(), [LEGACY_FILE]);
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
    let marker = m.freedom.join(MIGRATED_FILE);
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), TWO_RECEIPTS);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&marker).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(std::fs::read_to_string(m.original()).unwrap(), TWO_RECEIPTS);
    assert_eq!(m.start(), (Handover::Dropped(true), 2.0));
    assert_eq!(m.profile_files(), NONE);
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
    assert_eq!(m.start(), (Handover::Absent, 2.0));
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
}

/// Step 2: a `.migrated` at the profile's root too: the root's file is
/// dropped there, unread, as the import drops a stray; that `.migrated`
/// stays, and nothing is copied or imported.
#[test]
fn a_stray_at_the_profiles_root_is_dropped_there_and_not_copied() {
    let m = moved();
    std::fs::write(m.original(), RECEIPTS).unwrap();
    std::fs::write(m.profile.join(MIGRATED_FILE), "[]").unwrap();
    assert_eq!(m.start(), (Handover::Stray(true), 0.0));
    assert_eq!(m.profile_files(), [MIGRATED_FILE]);
    assert_eq!(m.freedom_files(), NONE);
}

/// Step 3: what the import can't read (a directory, past the bound, and on
/// Unix a link and a FIFO) stays at the profile's root, unread and
/// uncopied, at every start, and nothing is imported. A dangling link is
/// absent (step 1), as the import's check finds it.
#[test]
fn what_the_import_cannot_read_stays_at_the_profiles_root() {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut cases: Vec<(&str, Make)> = vec![
        (
            "directory",
            Box::new(|path: &Path| std::fs::create_dir(path).unwrap()),
        ),
        (
            "oversized",
            Box::new(|path: &Path| {
                let mut text = String::from("[");
                text.push_str(&" ".repeat(MAX_LEGACY_BYTES - 1));
                text.push(']');
                std::fs::write(path, text).unwrap();
            }),
        ),
    ];
    #[cfg(unix)]
    {
        cases.push((
            "link",
            Box::new(|path: &Path| {
                let target = path.with_file_name("elsewhere.json");
                std::fs::write(&target, RECEIPTS).unwrap();
                std::os::unix::fs::symlink(&target, path).unwrap();
            }),
        ));
        cases.push((
            "fifo",
            Box::new(|path: &Path| {
                let made = std::process::Command::new("mkfifo")
                    .arg(path)
                    .status()
                    .unwrap();
                assert!(made.success());
            }),
        ));
    }
    for (name, make) in &cases {
        let m = moved();
        make(&m.original());
        let kind = std::fs::symlink_metadata(m.original()).unwrap().file_type();
        let len = std::fs::symlink_metadata(m.original()).unwrap().len();
        for _ in 0..2 {
            assert_eq!(m.start(), (Handover::Kept, 0.0), "{name}");
            let after = std::fs::symlink_metadata(m.original()).unwrap();
            assert_eq!(after.file_type(), kind, "{name}");
            assert_eq!(after.len(), len, "{name}");
            assert_eq!(m.freedom_files(), NONE, "{name}");
        }
    }
    #[cfg(unix)]
    {
        let m = moved();
        std::os::unix::fs::symlink("gone", m.original()).unwrap();
        assert_eq!(m.start(), (Handover::Absent, 0.0));
        assert!(m.original().is_symlink());
        assert_eq!(m.freedom_files(), NONE);
    }
}

/// Bad JSON and refused rows: copied, the copy refused by the import and
/// left unrenamed beside the original; each later start finds the copy
/// (step 5), and the import retries on it, refusing it again, the
/// original still at the root.
#[test]
fn refused_receipts_keep_the_copy_and_the_original_and_retry() {
    for text in [
        r#"[{"id": "r1","#.to_owned(),
        format!("[{}, null]", &RECEIPTS[1..RECEIPTS.len() - 1]),
    ] {
        let m = moved();
        std::fs::write(m.original(), &text).unwrap();
        assert_eq!(m.start(), (Handover::Copied(Done::Durable), 0.0), "{text}");
        assert_eq!(m.profile_files(), [LEGACY_FILE], "{text}");
        assert_eq!(m.freedom_files(), [LEGACY_FILE], "{text}");
        for _ in 0..2 {
            assert_eq!(m.start(), (Handover::Waiting, 0.0), "{text}");
            assert_eq!(m.profile_files(), [LEGACY_FILE], "{text}");
            assert_eq!(m.freedom_files(), [LEGACY_FILE], "{text}");
        }
        // What the first open ran: the import, refusing the copy.
        let mut payments = open(&m.freedom);
        assert_eq!(
            Store::import(&m.freedom, &mut payments, || 1.0),
            Legacy::Kept,
            "{text}"
        );
        assert_eq!(
            std::fs::read_to_string(m.freedom.join(LEGACY_FILE)).unwrap(),
            text
        );
        assert_eq!(std::fs::read_to_string(m.original()).unwrap(), text);
    }
}

/// The import's database write failing (its connection read-only, as
/// `busy_and_failed_writes` refuses a write): the copy and the original
/// both stay, and the next start's import commits from the copy, the one
/// after dropping the original.
#[test]
fn a_failed_database_write_keeps_both_and_the_next_start_imports() {
    let m = moved();
    std::fs::write(m.original(), TWO_RECEIPTS).unwrap();
    let handover = hand_over(&m.profile, &m.freedom, &NoHooks);
    assert_eq!(handover, Handover::Copied(Done::Durable));
    let import = handover.import(&m.profile, &m.freedom);
    assert_eq!(import, Import::at(m.freedom.clone()));
    let conn = sqlite::open(&m.freedom.join(DB_FILE), &SCHEMA).unwrap();
    conn.pragma_update(None, "query_only", true).unwrap();
    let mut payments = Payments::new(conn);
    assert_eq!(
        Store::import(&import.root, &mut payments, || 1.0),
        Legacy::Kept
    );
    drop(payments);
    assert_eq!(m.profile_files(), [LEGACY_FILE]);
    assert_eq!(m.freedom_files(), [LEGACY_FILE]);
    assert_eq!(m.start(), (Handover::Waiting, 2.0));
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
    assert_eq!(m.profile_files(), [LEGACY_FILE]);
    assert_eq!(m.start(), (Handover::Dropped(true), 2.0));
    assert_eq!(m.profile_files(), NONE);
}

/// The states a crash leaves after the copy, each built on disk, and the
/// two-copy states among them: the original with its copy, before the
/// import's commit and after it (its rename to `.migrated` lost); the
/// original with the copy's `.migrated`; the `.migrated` alone, the
/// original removed. Each converges at the next starts with every row
/// imported once (`import_legacy` skipping what it imported already).
#[test]
fn the_crash_states_converge_with_every_row_once() {
    // Copy visible, import not committed.
    let m = moved();
    std::fs::write(m.original(), TWO_RECEIPTS).unwrap();
    std::fs::write(m.freedom.join(LEGACY_FILE), TWO_RECEIPTS).unwrap();
    assert_eq!(m.start(), (Handover::Waiting, 2.0));
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
    assert_eq!(m.start(), (Handover::Dropped(true), 2.0));
    assert_eq!(m.start(), (Handover::Absent, 2.0));

    // Import committed, its rename lost: the copy back without `.migrated`.
    let m = moved();
    std::fs::write(m.original(), TWO_RECEIPTS).unwrap();
    std::fs::write(m.freedom.join(LEGACY_FILE), TWO_RECEIPTS).unwrap();
    assert_eq!(
        open(&m.freedom)
            .import_legacy(TWO_RECEIPTS, || 1.0)
            .unwrap(),
        2
    );
    let rows = table_at(&m.freedom);
    assert_eq!(m.start(), (Handover::Waiting, 2.0));
    assert_eq!(table_at(&m.freedom), rows);
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
    assert_eq!(m.start(), (Handover::Dropped(true), 2.0));
    assert_eq!(table_at(&m.freedom), rows);

    // The `.migrated` visible, the original still at the root.
    let m = moved();
    std::fs::write(m.original(), TWO_RECEIPTS).unwrap();
    std::fs::write(m.freedom.join(MIGRATED_FILE), TWO_RECEIPTS).unwrap();
    open(&m.freedom)
        .import_legacy(TWO_RECEIPTS, || 1.0)
        .unwrap();
    assert_eq!(m.start(), (Handover::Dropped(true), 2.0));
    assert_eq!(m.profile_files(), NONE);
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);

    // The original removed: nothing left to do.
    assert_eq!(m.start(), (Handover::Absent, 2.0));
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
}

/// Step 6: a file in the Freedom root under either name that isn't the
/// copy (other bytes, a directory, a link to the same bytes), even beside
/// one that is (a `.migrated` of other bytes beside a true copy, a true
/// `.migrated` beside a copy of other bytes, a directory or a link): a
/// conflict. Nothing is copied, removed or renamed, the original stays at
/// the profile's root, no legacy row comes from any file, and the database
/// serves. Each start checks again; removing one by hand settles it.
#[test]
fn a_file_in_the_freedom_root_that_isnt_the_copy_is_a_conflict() {
    let other = RECEIPTS.replace("r1", "r9");
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut cases: Vec<(&str, Make)> = vec![
        (
            "copy, other bytes",
            Box::new(|freedom: &Path| {
                std::fs::write(freedom.join(LEGACY_FILE), RECEIPTS.replace("r1", "r9")).unwrap();
            }),
        ),
        (
            "migrated, other bytes",
            Box::new(|freedom: &Path| {
                std::fs::write(freedom.join(MIGRATED_FILE), RECEIPTS.replace("r1", "r9")).unwrap();
            }),
        ),
        (
            "copy, a directory",
            Box::new(|freedom: &Path| std::fs::create_dir(freedom.join(LEGACY_FILE)).unwrap()),
        ),
        (
            "migrated other, beside a true copy",
            Box::new(|freedom: &Path| {
                std::fs::write(freedom.join(LEGACY_FILE), RECEIPTS).unwrap();
                std::fs::write(freedom.join(MIGRATED_FILE), RECEIPTS.replace("r1", "r9")).unwrap();
            }),
        ),
        (
            "true migrated, beside a copy of other bytes",
            Box::new(|freedom: &Path| {
                std::fs::write(freedom.join(MIGRATED_FILE), RECEIPTS).unwrap();
                std::fs::write(freedom.join(LEGACY_FILE), RECEIPTS.replace("r1", "r9")).unwrap();
            }),
        ),
        (
            "true migrated, beside a directory",
            Box::new(|freedom: &Path| {
                std::fs::write(freedom.join(MIGRATED_FILE), RECEIPTS).unwrap();
                std::fs::create_dir(freedom.join(LEGACY_FILE)).unwrap();
            }),
        ),
    ];
    #[cfg(unix)]
    cases.push((
        "copy, a link to the same bytes",
        Box::new(|freedom: &Path| {
            let target = freedom.join("same.json");
            std::fs::write(&target, RECEIPTS).unwrap();
            std::os::unix::fs::symlink(&target, freedom.join(LEGACY_FILE)).unwrap();
        }),
    ));
    #[cfg(unix)]
    cases.push((
        "true migrated, beside a link to the same bytes",
        Box::new(|freedom: &Path| {
            std::fs::write(freedom.join(MIGRATED_FILE), RECEIPTS).unwrap();
            let target = freedom.join("same.json");
            std::fs::write(&target, RECEIPTS).unwrap();
            std::os::unix::fs::symlink(&target, freedom.join(LEGACY_FILE)).unwrap();
        }),
    ));
    let snapshot = |dir: &Path| -> Vec<(String, Option<Vec<u8>>)> {
        files(dir)
            .into_iter()
            .filter(|name| name != "freedom")
            .map(|name| {
                let bytes = std::fs::read(dir.join(&name)).ok();
                (name, bytes)
            })
            .collect()
    };
    for (name, make) in &cases {
        let m = moved();
        std::fs::write(m.original(), RECEIPTS).unwrap();
        make(&m.freedom);
        let (profile, freedom) = (snapshot(&m.profile), snapshot(&m.freedom));
        for _ in 0..2 {
            let (handover, mut store) = m.start_store(&NoHooks);
            assert_eq!(handover, Handover::Conflict, "{name}");
            assert_eq!(count(&mut store), 0.0, "{name}");
            assert_eq!(snapshot(&m.profile), profile, "{name}");
            assert_eq!(snapshot(&m.freedom), freedom, "{name}");
            // Payments still served.
            call(
                &mut store,
                "payments.append",
                r#"{"entry":{"kind":"x402","chainId":1,"amount":"1","createdAt":5}}"#,
            )
            .unwrap();
            call(&mut store, "payments.clear", "{}").unwrap();
        }
    }
    // Settled by hand: the other file removed, the next start copies and
    // imports the profile's root's.
    let m = moved();
    std::fs::write(m.original(), RECEIPTS).unwrap();
    std::fs::write(m.freedom.join(LEGACY_FILE), &other).unwrap();
    assert_eq!(m.start(), (Handover::Conflict, 0.0));
    std::fs::remove_file(m.freedom.join(LEGACY_FILE)).unwrap();
    assert_eq!(m.start(), (Handover::Copied(Done::Durable), 1.0));
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
}

/// A crashed copy's temp (fc-store's name for this file) is removed by the
/// next start before it copies; a copy whose write fails before its rename
/// leaves no copy and no temp, the root untouched and nothing imported, and
/// the next start copies again.
#[test]
fn a_crashed_or_failed_copy_is_made_again() {
    let m = moved();
    std::fs::write(m.original(), RECEIPTS).unwrap();
    let temp = format!(".{LEGACY_FILE}.4242.0.tmp");
    std::fs::write(m.freedom.join(&temp), &RECEIPTS[..10]).unwrap();
    // Another file's temp isn't this one's.
    std::fs::write(m.freedom.join(".phone-payments.json.4242.0.tmp"), "").unwrap();
    assert_eq!(m.start(), (Handover::Copied(Done::Durable), 1.0));
    assert_eq!(
        m.freedom_files(),
        [".phone-payments.json.4242.0.tmp", MIGRATED_FILE]
    );

    for failing in [
        Failing(&[Step::Write]),
        Failing(&[Step::Fsync]),
        Failing(&[Step::Rename]),
    ] {
        let step = failing.0;
        let m = moved();
        std::fs::write(m.original(), RECEIPTS).unwrap();
        assert_eq!(
            m.start_with(&failing),
            (Handover::CopyFailed, 0.0),
            "{step:?}"
        );
        assert_eq!(m.freedom_files(), NONE, "{step:?}");
        assert_eq!(m.profile_files(), [LEGACY_FILE], "{step:?}");
        assert_eq!(std::fs::read_to_string(m.original()).unwrap(), RECEIPTS);
        assert_eq!(
            m.start(),
            (Handover::Copied(Done::Durable), 1.0),
            "{step:?}"
        );
        assert_eq!(m.freedom_files(), [MIGRATED_FILE], "{step:?}");
    }
}

/// A forced flush failure: of the copy (in place, not durable, imported
/// all the same), and of the Freedom root's sync before the original's
/// removal, which leaves the original for the next start.
#[test]
fn a_failed_flush_leaves_the_original() {
    let m = moved();
    std::fs::write(m.original(), RECEIPTS).unwrap();
    let flush = Failing(&[Step::Flush]);
    assert_eq!(
        m.start_with(&flush),
        (Handover::Copied(Done::NotDurable), 1.0)
    );
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
    assert_eq!(m.profile_files(), [LEGACY_FILE]);
    assert_eq!(m.start_with(&flush), (Handover::Dropped(false), 1.0));
    assert_eq!(m.profile_files(), [LEGACY_FILE]);
    assert_eq!(m.freedom_files(), [MIGRATED_FILE]);
    assert_eq!(m.start(), (Handover::Dropped(true), 1.0));
    assert_eq!(m.profile_files(), NONE);
}

/// The old layout: the profile's root is the Freedom root, by its path or
/// (Unix) through a link. The hand-over does nothing and the import reads
/// the profile's root, renaming the file there, as before; a hello without
/// `user_data_dir` imports at the Freedom root ([`Import::at`]), as
/// [`named`] does.
#[test]
fn the_old_layout_imports_at_its_root_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join(LEGACY_FILE), RECEIPTS).unwrap();
    let handover = hand_over(root, root, &Failing(&[Step::Write, Step::Flush]));
    assert_eq!(handover, Handover::Same);
    let import = handover.import(root, root);
    assert_eq!(import, Import::at(root.to_path_buf()));
    let mut store = Store::new();
    store.configure(root.to_path_buf(), import);
    assert_eq!(count(&mut store), 1.0);
    assert_eq!(files(root), [MIGRATED_FILE]);
    #[cfg(unix)]
    {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("userData");
        std::fs::create_dir(&root).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        std::fs::write(root.join(LEGACY_FILE), RECEIPTS).unwrap();
        let handover = hand_over(&link, &root, &NoHooks);
        assert_eq!(handover, Handover::Same);
        assert_eq!(handover.import(&link, &root), Import::at(link.clone()));
        assert_eq!(files(&root), [LEGACY_FILE]);
    }
}

/// A valid receipts file that isn't the profile's root's.
const UNRELATED: &str =
    r#"[{"id":"r7","settledAt":1699000200,"status":"settled","chainId":8453,"amount":"900"}]"#;

/// Hooks that put [`UNRELATED`] in the Freedom root as the hand-over
/// reaches `at` (a copy's write step, or step 4's sync as `Flush`), and
/// fail that step if `fail`: a file that turns up there during the start.
struct Plant {
    at: Step,
    fail: bool,
    path: PathBuf,
}

impl Hooks for Plant {
    fn fails(&self, step: Step) -> bool {
        if step != self.at {
            return false;
        }
        std::fs::write(&self.path, UNRELATED).unwrap();
        self.fail
    }
}

/// Only a copy proved (step 5) or made (step 7) is imported: after every
/// other outcome a valid, unrelated `x402-receipts.json` in the Freedom
/// root is neither imported, renamed nor removed, and no legacy row
/// appears, the database serving. Steps 1, 2 and 3 find it there before
/// the start; a failed copy and step 4 (either way) find it turning up
/// during the start, since one there before, beside a copy or `.migrated`,
/// is step 6's conflict. After step 4 a copy of the same bytes as the
/// `.migrated` stays too.
#[test]
fn an_unproven_file_in_the_freedom_root_is_never_imported() {
    let unrelated_first = |make_root: &dyn Fn(&Moved)| {
        let m = moved();
        make_root(&m);
        std::fs::write(m.freedom.join(LEGACY_FILE), UNRELATED).unwrap();
        m
    };
    let unchanged = |m: &Moved, context: &str| {
        assert_eq!(
            std::fs::read_to_string(m.freedom.join(LEGACY_FILE)).unwrap(),
            UNRELATED,
            "{context}"
        );
    };

    let m = unrelated_first(&|_| {});
    assert_eq!(m.start(), (Handover::Absent, 0.0));
    assert_eq!(m.freedom_files(), [LEGACY_FILE]);
    unchanged(&m, "absent");

    let m = unrelated_first(&|m| {
        std::fs::write(m.original(), RECEIPTS).unwrap();
        std::fs::write(m.profile.join(MIGRATED_FILE), "[]").unwrap();
    });
    assert_eq!(m.start(), (Handover::Stray(true), 0.0));
    assert_eq!(m.profile_files(), [MIGRATED_FILE]);
    assert_eq!(m.freedom_files(), [LEGACY_FILE]);
    unchanged(&m, "stray");

    let m = unrelated_first(&|m| std::fs::create_dir(m.original()).unwrap());
    assert_eq!(m.start(), (Handover::Kept, 0.0));
    assert_eq!(m.freedom_files(), [LEGACY_FILE]);
    unchanged(&m, "kept");

    let m = moved();
    std::fs::write(m.original(), RECEIPTS).unwrap();
    let plant = Plant {
        at: Step::Rename,
        fail: true,
        path: m.freedom.join(LEGACY_FILE),
    };
    assert_eq!(m.start_with(&plant), (Handover::CopyFailed, 0.0));
    assert_eq!(m.profile_files(), [LEGACY_FILE]);
    assert_eq!(m.freedom_files(), [LEGACY_FILE]);
    unchanged(&m, "copy failed");

    for (fail, dropped) in [(false, true), (true, false)] {
        let m = moved();
        std::fs::write(m.original(), RECEIPTS).unwrap();
        std::fs::write(m.freedom.join(MIGRATED_FILE), RECEIPTS).unwrap();
        let plant = Plant {
            at: Step::Flush,
            fail,
            path: m.freedom.join(LEGACY_FILE),
        };
        assert_eq!(m.start_with(&plant), (Handover::Dropped(dropped), 0.0));
        assert_eq!(m.freedom_files(), [LEGACY_FILE, MIGRATED_FILE]);
        unchanged(&m, "dropped");
        assert_eq!(
            std::fs::read_to_string(m.freedom.join(MIGRATED_FILE)).unwrap(),
            RECEIPTS
        );
        assert_eq!(m.original().exists(), !dropped);
    }

    // Step 4 beside a copy of the same bytes: the original goes, the copy
    // stays, and nothing is imported.
    let m = moved();
    std::fs::write(m.original(), RECEIPTS).unwrap();
    std::fs::write(m.freedom.join(MIGRATED_FILE), RECEIPTS).unwrap();
    std::fs::write(m.freedom.join(LEGACY_FILE), RECEIPTS).unwrap();
    let (handover, mut store) = m.start_store(&NoHooks);
    assert_eq!(handover, Handover::Dropped(true));
    assert_eq!(count(&mut store), 0.0);
    assert_eq!(m.profile_files(), NONE);
    assert_eq!(m.freedom_files(), [LEGACY_FILE, MIGRATED_FILE]);
    call(
        &mut store,
        "payments.append",
        r#"{"entry":{"kind":"x402","chainId":1,"amount":"1","createdAt":5}}"#,
    )
    .unwrap();
}
