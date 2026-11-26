//! The stores' files: the loads (a file that doesn't parse, one past the
//! bound, a v1 file, one the core can't read), the manifest store's backup,
//! and the history's open (the schema, the legacy import, the sweep, the
//! bound) and statements.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::Path;

use fc_swarm_provider::stores::history::{self, Bind, Cell, Statement};

use super::*;

const NOW: u64 = 1_767_225_600_123;

/// A v2 store with one site and one feed.
const V2: &str = r#"{"version":2,"nextPublisherKeyIndex":0,"origins":{"https://a.example":{"activeIdentityId":"bee-wallet","identities":{"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null}},"feedGranted":true,"grantedAt":1,"feeds":{"blog":{"topic":"t"}}}}}"#;

fn place(root: &Path) -> Place {
    Place {
        root: root.to_path_buf(),
        history_import: Import::at(root.to_path_buf()),
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn names(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn feeds_load_as_load_feeds_reads_them() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let file = root.join(feeds::FILE_NAME);
    // None: the empty store, nothing written.
    assert_eq!(load_feeds(root, NOW), FeedStore::empty());
    assert!(names(root).is_empty());

    // A v2 file, as it is.
    std::fs::write(&file, V2).unwrap();
    let store = load_feeds(root, NOW);
    assert!(store.has_feed_grant(&JsString::from("https://a.example")));
    assert_eq!(names(root), ["swarm-feeds.json"]);

    // A file that doesn't parse: copied aside, the first free name each
    // time, and left in place until the next change writes the empty store.
    std::fs::write(&file, "{not json").unwrap();
    assert_eq!(load_feeds(root, NOW), FeedStore::empty());
    assert_eq!(load_feeds(root, NOW), FeedStore::empty());
    assert_eq!(
        names(root),
        [
            "swarm-feeds.corrupt-1.json",
            "swarm-feeds.corrupt.json",
            "swarm-feeds.json"
        ]
    );
    assert_eq!(read(&root.join("swarm-feeds.corrupt.json")), "{not json");
    assert_eq!(read(&file), "{not json");

    // Past the bound by a byte: read, and copied aside as one that doesn't
    // parse.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let file = root.join(feeds::FILE_NAME);
    let mut big = b"{}".to_vec();
    big.resize(feeds::MAX_FILE_BYTES + 1, b' ');
    std::fs::write(&file, &big).unwrap();
    assert_eq!(load_feeds(root, NOW), FeedStore::empty());
    assert_eq!(
        std::fs::metadata(root.join("swarm-feeds.corrupt.json"))
            .unwrap()
            .len(),
        big.len() as u64
    );

    // Past it by more: unreadable under 0001's rules, so renamed aside.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let file = root.join(feeds::FILE_NAME);
    big.resize(feeds::MAX_FILE_BYTES + 2, b' ');
    std::fs::write(&file, &big).unwrap();
    assert_eq!(load_feeds(root, NOW), FeedStore::empty());
    assert_eq!(names(root), ["swarm-feeds.corrupt.json"]);

    // A directory in its place: renamed aside too.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir(root.join(feeds::FILE_NAME)).unwrap();
    assert_eq!(load_feeds(root, NOW), FeedStore::empty());
    assert_eq!(names(root), ["swarm-feeds.corrupt.json"]);
}

#[test]
fn a_v1_file_is_kept_aside_and_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let file = root.join(feeds::FILE_NAME);
    let v1 = r#"{"version":1,"nextPublisherKeyIndex":0,"origins":{"https://a.example":{"identityMode":"bee-wallet","feedGranted":true,"grantedAt":5,"feeds":{"blog":{"topic":"t"}}}}}"#;
    std::fs::write(&file, v1).unwrap();
    let store = load_feeds(root, NOW);
    assert_eq!(read(&root.join("swarm-feeds.v1-backup.json")), v1);
    // The migration, written over the file as the codec gives its text.
    assert_eq!(read(&file), store.text().unwrap());
    assert!(read(&file).contains("\"version\": 2"));
    assert!(
        store
            .feed(
                &JsString::from("https://a.example"),
                &JsString::from("blog")
            )
            .is_some()
    );
}

#[test]
fn the_feed_stores_writes_are_durable_and_whole() {
    let dir = tempfile::tempdir().unwrap();
    let Loaded { mut files, .. } = Files::load(place(dir.path()), NOW);
    files.write_feeds(V2).unwrap();
    assert_eq!(read(&dir.path().join(feeds::FILE_NAME)), V2);
    // No temp file is left beside it.
    let feeds: Vec<String> = names(dir.path())
        .into_iter()
        .filter(|name| !name.starts_with("publish-history"))
        .collect();
    assert_eq!(feeds, ["swarm-feeds.json"]);
}

#[test]
fn the_manifest_store_reads_its_backup_and_saves_one() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let file = root.join(manifests::FILE_NAME);
    let bak = root.join(manifests::BACKUP_NAME);
    // None: an empty store, loaded.
    assert!(load_manifests(root).is_loaded());
    // A good file.
    let good = r#"{"version":1,"records":{}}"#;
    std::fs::write(&file, good).unwrap();
    assert!(load_manifests(root).is_loaded());
    // A file that doesn't parse: its backup.
    std::fs::write(&file, "{").unwrap();
    assert!(!load_manifests(root).is_loaded());
    std::fs::write(&bak, good).unwrap();
    assert!(load_manifests(root).is_loaded());
    // Past the bound: its backup too.
    let mut big = good.as_bytes().to_vec();
    big.resize(manifests::MAX_FILE_BYTES + 5, b' ');
    std::fs::write(&file, &big).unwrap();
    assert!(load_manifests(root).is_loaded());
    std::fs::remove_file(&bak).unwrap();
    assert!(!load_manifests(root).is_loaded());

    // A save copies the file as it stands to `.bak` first.
    std::fs::write(&file, good).unwrap();
    let Loaded { mut files, .. } = Files::load(place(root), NOW);
    let next = r#"{"version":1,"records":{"k":{}}}"#;
    files
        .save_manifests(&Save {
            text: next.to_owned(),
            backup: true,
        })
        .unwrap();
    assert_eq!(read(&bak), good);
    assert_eq!(read(&file), next);
    // Unless the store was read from it.
    files
        .save_manifests(&Save {
            text: good.to_owned(),
            backup: false,
        })
        .unwrap();
    assert_eq!(read(&bak), good);
    assert_eq!(read(&file), good);
}

/// A connection of the test's own, as another reader sees the database.
fn reader(root: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(root.join(history::FILE_NAME)).unwrap()
}

fn rows(root: &Path) -> Vec<(i64, String, Option<String>)> {
    let conn = reader(root);
    let mut statement = conn
        .prepare("SELECT id, status, error_message FROM publishes ORDER BY id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn insert(status: &str, started_at: f64) -> Statement {
    let entry = fc_json::parse(&format!(
        r#"{{"type":"data","name":"n","status":"{status}","origin":"https://a.example"}}"#
    ))
    .unwrap();
    let mut statement = history::add_entry(&entry, 0).unwrap();
    statement.params[9] = Bind::Real(started_at);
    statement
}

#[test]
fn the_history_opens_with_the_references_schema() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let Loaded { mut files, .. } = Files::load(place(root), NOW);
    let conn = reader(root);
    let version: i32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, history::SCHEMA_VERSION);
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let ddl: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'publishes'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // SQLite keeps the statement's text, but for `IF NOT EXISTS`.
    let body = ddl.strip_prefix("CREATE TABLE publishes").unwrap();
    assert!(history::DDL.contains(body), "{ddl}");

    // An insert answers its rowid; the row reads back as SQLite answers it.
    let id = files
        .history_insert(&insert("uploading", 7.0), NOW)
        .unwrap();
    assert_eq!(id, 1);
    files
        .history(
            &[history::update_entry(
                &fc_json::JsValue::Number(1.0),
                &fc_json::parse(r#"{"status":"completed","reference":"ab"}"#).unwrap(),
                NOW,
            )
            .unwrap()],
            NOW,
        )
        .unwrap();
    let read = files.history_rows(&history::by_rowid(1), NOW).unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0][3], Cell::Text("completed".to_owned()));
    assert_eq!(read[0][4], Cell::Text("ab".to_owned()));
    #[expect(clippy::cast_possible_wrap, reason = "a test clock")]
    let completed = NOW as i64;
    assert_eq!(read[0][11], Cell::Integer(completed));
    let entry = history::entry(&read[0]).unwrap();
    assert_eq!(
        entry.get("status").and_then(|v| v.as_str()),
        Some("completed")
    );
}

#[test]
fn an_open_sweeps_uploading_rows_and_keeps_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    {
        let Loaded { mut files, .. } = Files::load(place(root), NOW);
        files
            .history_insert(&insert("uploading", 1.0), NOW)
            .unwrap();
        files
            .history_insert(&insert("completed", 2.0), NOW)
            .unwrap();
    }
    // The next start: the row left uploading is failed, the other kept.
    let _ = Files::load(place(root), NOW + 5);
    assert_eq!(
        rows(root),
        [
            (
                1,
                "failed".to_owned(),
                Some(history::ORPHAN_SWEEP_MESSAGE.to_owned())
            ),
            (2, "completed".to_owned(), None),
        ]
    );
    // Past the bound at the open: trimmed to it, finished rows first,
    // oldest first.
    {
        let conn = reader(root);
        let tx = conn.unchecked_transaction().unwrap();
        for i in 0..history::MAX_ROWS {
            tx.execute(
                "INSERT INTO publishes (type, status, started_at) VALUES ('data', 'completed', ?)",
                [i64::try_from(i).unwrap() + 10],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let _ = Files::load(place(root), NOW + 6);
    let conn = reader(root);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM publishes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, i64::try_from(history::MAX_ROWS).unwrap());
    let oldest: i64 = conn
        .query_row("SELECT MIN(id) FROM publishes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(oldest, 3, "the two oldest finished rows went");
}

#[test]
fn the_legacy_history_is_imported_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let legacy = root.join(PUBLISH_HISTORY.file);
    let migrated = root.join(PUBLISH_HISTORY.migrated);
    std::fs::write(
        &legacy,
        r#"{"entries":[{"type":"file","name":"a.txt","status":"completed","reference":"aa","timestamp":"2026-01-01T00:00:00.000Z"},{"name":"b","status":"uploading","timestamp":"2026-01-02T00:00:00.000Z"}]}"#,
    )
    .unwrap();
    let _ = Files::load(place(root), NOW);
    // Imported in one transaction, renamed, and the uploading one swept.
    assert!(!legacy.exists());
    assert!(migrated.exists());
    assert_eq!(
        rows(root),
        [
            (1, "completed".to_owned(), None),
            (
                2,
                "failed".to_owned(),
                Some(history::ORPHAN_SWEEP_MESSAGE.to_owned())
            ),
        ]
    );
    // A stray copy beside the `.migrated` is removed, nothing imported.
    std::fs::write(&legacy, r#"{"entries":[{"name":"c"}]}"#).unwrap();
    let _ = Files::load(place(root), NOW);
    assert!(!legacy.exists());
    assert_eq!(rows(root).len(), 2);
    // One that doesn't parse stays, unimported.
    std::fs::remove_file(&migrated).unwrap();
    std::fs::write(&legacy, "{").unwrap();
    let _ = Files::load(place(root), NOW);
    assert!(legacy.exists());
    assert_eq!(rows(root).len(), 2);
    // A hand-over that skipped the import leaves a good one too.
    std::fs::write(&legacy, r#"{"entries":[{"name":"d"}]}"#).unwrap();
    let skipped = Place {
        root: root.to_path_buf(),
        history_import: Import {
            root: root.to_path_buf(),
            skip: true,
        },
    };
    let _ = Files::load(skipped, NOW);
    assert!(legacy.exists());
    assert_eq!(rows(root).len(), 2);
}

#[test]
fn a_history_that_wont_open_fails_each_statement_and_retries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Another schema's database: refused, nothing written.
    {
        let conn = reader(root);
        conn.execute_batch("PRAGMA user_version = 7;").unwrap();
    }
    let Loaded { mut files, .. } = Files::load(place(root), NOW);
    assert_eq!(
        files.history_insert(&insert("uploading", 1.0), NOW),
        Err(JsString::from(HISTORY_FAILED))
    );
    {
        let conn = reader(root);
        conn.execute_batch("PRAGMA user_version = 0;").unwrap();
    }
    // The next statement opens it.
    assert_eq!(files.history_insert(&insert("uploading", 1.0), NOW), Ok(1));
}
