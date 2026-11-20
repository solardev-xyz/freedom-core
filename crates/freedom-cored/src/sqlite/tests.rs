//! The schemas against the reference's (`vectors/sqlite.json`), and
//! [`open`]'s refusals.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

use super::{Error, Schema, open};

// The DDL each reference module runs, byte for byte: the template literal
// of `migrateDatabase` in freedom-browser's src/main/payment-history.js
// (fc-wallet-state's `payments::DDL`) and src/main/swarm/publish-history.js
// (sqlite.json's pin). SQLite keeps each statement's text in
// `sqlite_master`, so the vectors compare it too.
const PAYMENTS: Schema = crate::payments::SCHEMA;

const PUBLISHES: Schema = Schema {
    version: 1,
    ddl: r#"
      CREATE TABLE IF NOT EXISTS publishes (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        type          TEXT NOT NULL,
        name          TEXT,
        status        TEXT NOT NULL,
        reference     TEXT,
        bzz_url       TEXT,
        tag_uid       INTEGER,
        batch_id      TEXT,
        origin        TEXT,
        bytes_size    INTEGER,
        started_at    INTEGER NOT NULL,
        completed_at  INTEGER,
        error_message TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_publishes_started   ON publishes(started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_publishes_type      ON publishes(type);
      CREATE INDEX IF NOT EXISTS idx_publishes_status    ON publishes(status);
      CREATE INDEX IF NOT EXISTS idx_publishes_reference ON publishes(reference);
      CREATE INDEX IF NOT EXISTS idx_publishes_origin    ON publishes(origin);
    "#,
};

/// `databases`, through `fc_json`: `payments`' records hold escaped lone
/// surrogates (a string's code units spread into metadata), which
/// `serde_json` refuses.
fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sqlite.json");
    let all = fc_json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    let databases = all.get("databases").unwrap().stringify();
    serde_json::json!({ "databases": serde_json::from_str::<Value>(&databases).unwrap() })
}

/// `sqlite_master`'s rows in the order SQLite wrote them, as the generator
/// reads them.
fn schema_rows(conn: &Connection) -> Value {
    let mut statement = conn
        .prepare("SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY rowid")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok(json!({
                "type": row.get::<_, String>(0)?,
                "name": row.get::<_, String>(1)?,
                "tbl_name": row.get::<_, String>(2)?,
                "rootpage": row.get::<_, i64>(3)?,
                "sql": row.get::<_, Option<String>>(4)?,
            }))
        })
        .unwrap();
    Value::Array(rows.collect::<Result<_, _>>().unwrap())
}

fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

fn pragma(conn: &Connection, name: &str) -> Value {
    conn.query_row(&format!("PRAGMA {name}"), [], |row| {
        row.get::<_, rusqlite::types::Value>(0)
    })
    .map(|value| match value {
        rusqlite::types::Value::Integer(n) => json!(n),
        rusqlite::types::Value::Text(s) => json!(s),
        other => panic!("{name}: {other:?}"),
    })
    .unwrap()
}

/// Each database the core creates with the reference's DDL has the
/// reference's `sqlite_master` rows, `user_version` and journal mode, and
/// reopening it changes none of them.
#[test]
fn the_reference_schemas() {
    let vectors = vectors();
    let databases = vectors["databases"].as_array().unwrap();
    let files: Vec<&str> = databases
        .iter()
        .map(|db| db["file"].as_str().unwrap())
        .collect();
    assert_eq!(files, ["payment-history.sqlite", "publish-history.sqlite"]);
    let dir = tempfile::tempdir().unwrap();
    for db in databases {
        let file = db["file"].as_str().unwrap();
        let schema = match file {
            "payment-history.sqlite" => &PAYMENTS,
            _ => &PUBLISHES,
        };
        let path = dir.path().join(file);
        for round in ["created", "reopened"] {
            drop(open(&path, schema).unwrap());
            let conn = read_only(&path);
            assert_eq!(schema_rows(&conn), db["sqlite_master"], "{file} {round}");
            assert_eq!(pragma(&conn, "user_version"), db["user_version"], "{file}");
            assert_eq!(pragma(&conn, "journal_mode"), db["journal_mode"], "{file}");
        }
    }
}

/// A new database and its WAL are the user's alone (0001's mode `0600`).
#[cfg(unix)]
#[test]
fn a_new_database_is_the_users_alone() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payment-history.sqlite");
    let conn = open(&path, &PAYMENTS).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(
        mode(&dir.path().join("payment-history.sqlite-wal")) & 0o077,
        0
    );
    drop(conn);
}

/// A database of another `user_version` is refused, nothing written: not
/// its bytes, and not its journal mode (`journal_mode = WAL` persists).
#[test]
fn another_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payment-history.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", 2).unwrap();
    drop(conn);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(open(&path, &PAYMENTS), Err(Error::Version(2))));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!dir.path().join("payment-history.sqlite-wal").exists());
    let conn = read_only(&path);
    assert_eq!(schema_rows(&conn), json!([]));
    assert_eq!(pragma(&conn, "user_version"), json!(2));
    assert_eq!(pragma(&conn, "journal_mode"), json!("delete"));
}

/// Every connection syncs each commit (`synchronous` FULL, 2), on a new
/// database and on reopening an existing WAL one, whatever the build's
/// default.
#[test]
fn every_connection_syncs_each_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payment-history.sqlite");
    let conn = open(&path, &PAYMENTS).unwrap();
    assert_eq!(pragma(&conn, "synchronous"), json!(2));
    drop(conn);
    let conn = open(&path, &PAYMENTS).unwrap();
    assert_eq!(pragma(&conn, "synchronous"), json!(2));
    assert_eq!(pragma(&conn, "journal_mode"), json!("wal"));
}

/// Neither a link (to a valid database) nor a directory is opened.
#[test]
fn a_link_or_a_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.sqlite");
    drop(open(&target, &PAYMENTS).unwrap());
    let directory = dir.path().join("directory.sqlite");
    std::fs::create_dir(&directory).unwrap();
    assert!(matches!(open(&directory, &PAYMENTS), Err(Error::Refused)));
    #[cfg(unix)]
    {
        let link = dir.path().join("link.sqlite");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(open(&link, &PAYMENTS), Err(Error::Refused)));
    }
}

/// A directory reached through a link opens (macOS's temporary directories
/// are under `/var`, a link to `/private/var`), and the file's own name as a
/// link stays refused.
#[cfg(unix)]
#[test]
fn a_directory_through_a_link_opens() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("real")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("linked")).unwrap();
    let path = dir.path().join("linked/payment-history.sqlite");
    drop(open(&path, &PAYMENTS).unwrap());
    assert!(dir.path().join("real/payment-history.sqlite").is_file());
    drop(open(&path, &PAYMENTS).unwrap());
    std::os::unix::fs::symlink(&path, dir.path().join("real/link.sqlite")).unwrap();
    let link = dir.path().join("linked/link.sqlite");
    assert!(matches!(open(&link, &PAYMENTS), Err(Error::Refused)));
}

/// A database another user owns is refused. Only where the test can give a
/// file away (as root): skipped otherwise.
#[cfg(unix)]
#[test]
fn another_users_database_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payment-history.sqlite");
    drop(open(&path, &PAYMENTS).unwrap());
    let nobody = rustix::process::Uid::from_raw(65534);
    if rustix::fs::chown(&path, Some(nobody), None).is_err() {
        return;
    }
    assert!(matches!(open(&path, &PAYMENTS), Err(Error::Refused)));
}
