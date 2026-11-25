//! The Swarm stores on disk (design 0015, "The stores"; SWM-4 PR 7): the
//! files of fc-swarm-provider's codecs, under the Freedom root, once
//! `core.hello` names `swarm_stores` in `store_moved` (D3: one name for the
//! three, which SWM-6 moves together and SW-1 couples). Before the name the
//! swarm thread opens none of them, and every store-touching method answers
//! `not_moved` (the engine's door).
//!
//! - **`swarm-feeds.json`** ([`load_feeds`]): read under 0001's rules
//!   (`fc_store::file::read_file`), at most its 16 MiB bound and a byte, as
//!   `loadFeeds` reads it: a file that doesn't parse, or past the bound, is
//!   copied aside under the codec's backup name
//!   (`swarm-feeds.corrupt.json`, the first free `-<n>`), and the empty store
//!   that replaces it is written at the next change, as the reference does;
//!   a v1 file is copied aside (`swarm-feeds.v1-backup.json`) and its
//!   migration written over it, or, where that write fails, kept aside again
//!   as one that doesn't load. A file `read_file` refuses (not a regular file
//!   the user owns, or past the bound by more) can't be copied: it is renamed
//!   aside under that backup name instead. Each change is written by
//!   [`Files::write_feeds`], 0001's durable write (`write_file`) with the
//!   test hooks' `swarm_feeds:<step>` failures, from SW-1's keeper
//!   ([`fc_swarm_provider::machine::keeper::Keeper::change`]), which keeps
//!   the change in memory only once it is on disk (0013).
//! - **`swarm-manifest-grants.json`** ([`load_manifests`]): read at most its
//!   1 MiB bound and a byte, its `.bak` read where it isn't readable
//!   (`loadStore`); saved ([`Files::save_manifests`]) with the file as it
//!   stands copied to `.bak` first, unless the store was read from that
//!   backup (the codec's [`Save::backup`]), each durably, under the test
//!   hooks' `swarm_manifests:<step>`.
//! - **`publish-history.sqlite`** ([`History`]): opened through
//!   [`crate::sqlite::open`] with the reference's schema (`user_version` 1,
//!   WAL, the DDL byte for byte), then `history::open`'s work in the
//!   reference's order: the legacy `publish-history.json`'s one-shot import
//!   in one transaction, the file renamed `.migrated` once it commits (or a
//!   stray beside its `.migrated` removed), every row left `uploading`
//!   swept to `failed`, and the bound's trim. The legacy file is read where
//!   the hello's hand-over leaves it (design 0015, D10; 0017, C5:
//!   [`crate::payments_store::PUBLISH_HISTORY`]). The machines' statements
//!   run through [`Files::history`] and [`Files::history_insert`], their
//!   parameters bound as better-sqlite3 binds them ([`Bind`]) and rows read
//!   back as SQLite answers them ([`Cell`]). A failed open is tried again at
//!   the next statement; the test hooks' `swarm_history:write` fails a
//!   statement before it runs.
//!
//! Every write is synchronous on the swarm thread, so each finishes before
//! the thread takes the next store change ("SWM-4 must apply feed-store
//! writes in order"), and none lands between SW-1's re-check and its hold.
//!
//! A failure reads as a fixed text, never a path or an OS message (the
//! reference throws Node's `fs` or better-sqlite3's error there, whose text
//! names the file): [`FEEDS_WRITE_FAILED`], [`MANIFESTS_WRITE_FAILED`],
//! [`HISTORY_FAILED`].

use std::path::{Path, PathBuf};

use fc_json::JsString;
use fc_store::file::{Read, read_file, write_file};
use fc_store::fsx;
use fc_swarm_provider::stores::feeds::{self, FeedStore, LoadWrite, backup_name};
use fc_swarm_provider::stores::history::{self, Bind, Cell, Row, Statement};
use fc_swarm_provider::stores::manifests::{self, ManifestStore, Save};
use rusqlite::Connection;

use crate::payments_store::{Import, PUBLISH_HISTORY, drop_stray_of, not_imported_of};
use crate::sqlite::{self, Schema};
use crate::testhooks::GrantWrite;

/// The name `store_moved` gives the three Swarm stores (D3).
pub const STORE: &str = "swarm_stores";

/// The test hooks' store names (`FREEDOM_CORED_TEST_GRANT_WRITE_FAIL`).
pub const FEEDS_HOOKS: &str = "swarm_feeds";
pub const MANIFESTS_HOOKS: &str = "swarm_manifests";
pub const HISTORY_HOOKS: &str = "swarm_history";

/// What a caller reads when the feed store's write fails.
pub const FEEDS_WRITE_FAILED: &str = "The Swarm feed store could not be written";
/// What a caller reads when the manifest store's write fails.
pub const MANIFESTS_WRITE_FAILED: &str = "The Swarm manifest store could not be written";
/// What a caller reads when the publish history can't be opened, read or
/// written.
pub const HISTORY_FAILED: &str = "The publish history could not be read or written";

/// `publish-history.sqlite`'s schema, the reference's (`migrateDatabase`).
pub const HISTORY_SCHEMA: Schema = Schema {
    version: history::SCHEMA_VERSION,
    ddl: history::DDL,
};

/// Where the stores are, as the hello set them: the Freedom root, and
/// where the legacy history's import reads.
#[derive(Debug, Clone)]
pub struct Place {
    pub root: PathBuf,
    pub history_import: Import,
}

/// The stores' files: the Freedom root, and the history's one connection.
pub struct Files {
    root: PathBuf,
    history: History,
}

/// What [`Files::load`] read.
pub struct Loaded {
    pub feeds: FeedStore,
    pub manifests: ManifestStore,
    pub files: Files,
}

impl Files {
    /// The three stores as the swarm thread starts with them, at the wall
    /// clock `now_ms` (`Date.now()` for a v1 migration's grants and the
    /// history's sweep).
    pub fn load(place: Place, now_ms: u64) -> Loaded {
        let feeds = load_feeds(&place.root, now_ms);
        let manifests = load_manifests(&place.root);
        let mut history = History {
            path: place.root.join(history::FILE_NAME),
            import: place.history_import,
            conn: None,
        };
        // Opened now, as the stores load at the thread's start (D3); a
        // failure is tried again at the first statement.
        let _ = history.conn(now_ms);
        Loaded {
            feeds,
            manifests,
            files: Files {
                root: place.root,
                history,
            },
        }
    }

    /// `swarm-feeds.json`'s durable write of `text` (the keeper's write).
    pub fn write_feeds(&mut self, text: &str) -> Result<(), JsString> {
        write_file(
            &self.root.join(feeds::FILE_NAME),
            text.as_bytes(),
            &GrantWrite(FEEDS_HOOKS),
        )
        .map(drop)
        .map_err(|e| {
            crate::log::error(
                "swarm: cannot write swarm-feeds.json",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
            JsString::from(FEEDS_WRITE_FAILED)
        })
    }

    /// `saveStore()`: the file as it stands copied to `.bak` first where
    /// `save` says so (a missing file has nothing to copy), then the text,
    /// each durably.
    pub fn save_manifests(&mut self, save: &Save) -> Result<(), JsString> {
        let hooks = GrantWrite(MANIFESTS_HOOKS);
        let failed = |e: std::io::Error| {
            crate::log::error(
                "swarm: cannot write swarm-manifest-grants.json",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
            JsString::from(MANIFESTS_WRITE_FAILED)
        };
        let file = self.root.join(manifests::FILE_NAME);
        if save.backup {
            match read_file(&file, manifests::MAX_FILE_BYTES + 1) {
                Read::Bytes(bytes) => {
                    write_file(&self.root.join(manifests::BACKUP_NAME), &bytes, &hooks)
                        .map(drop)
                        .map_err(failed)?;
                }
                Read::Missing => {}
                // `fs.copyFileSync` of a file the core can't read throws.
                Read::Unreadable => {
                    return Err(failed(std::io::Error::other("unreadable")));
                }
            }
        }
        write_file(&file, save.text.as_bytes(), &hooks)
            .map(drop)
            .map_err(failed)
    }

    /// The history's statements, in order: the first that fails stops the
    /// rest.
    pub fn history(&mut self, statements: &[Statement], now_ms: u64) -> Result<(), JsString> {
        let conn = self.history.writable(now_ms)?;
        for statement in statements {
            execute(conn, statement).map_err(history_failed)?;
        }
        Ok(())
    }

    /// One `INSERT`: the new row's rowid.
    pub fn history_insert(&mut self, statement: &Statement, now_ms: u64) -> Result<i64, JsString> {
        let conn = self.history.writable(now_ms)?;
        execute(conn, statement).map_err(history_failed)?;
        Ok(conn.last_insert_rowid())
    }

    /// One statement: the rows it changed (`swarm.history`'s `clear` and
    /// `remove`).
    pub fn history_run(&mut self, statement: &Statement, now_ms: u64) -> Result<usize, JsString> {
        let conn = self.history.writable(now_ms)?;
        execute(conn, statement).map_err(history_failed)
    }

    /// `swarm-manifest-grants.json`'s bytes, as a store op loads them while
    /// the store isn't loaded (`loadStore`): a file `read_file` refuses
    /// reads as one that doesn't parse, so its backup is read.
    pub fn read_manifests(&mut self) -> Option<Vec<u8>> {
        match read_file(
            &self.root.join(manifests::FILE_NAME),
            manifests::MAX_FILE_BYTES + 1,
        ) {
            Read::Missing => None,
            Read::Bytes(bytes) => Some(bytes),
            Read::Unreadable => Some(Vec::new()),
        }
    }

    /// Its `.bak` copy's bytes, where the file can't be read.
    pub fn read_manifests_backup(&mut self) -> Option<Vec<u8>> {
        match read_file(
            &self.root.join(manifests::BACKUP_NAME),
            manifests::MAX_FILE_BYTES + 1,
        ) {
            Read::Bytes(bytes) => Some(bytes),
            Read::Missing | Read::Unreadable => None,
        }
    }

    /// A query's rows, as SQLite answers them: `swarm.history`'s reads.
    pub fn history_rows(
        &mut self,
        statement: &Statement,
        now_ms: u64,
    ) -> Result<Vec<Row>, JsString> {
        let conn = self.history.conn(now_ms)?;
        query(conn, statement).map_err(history_failed)
    }

    /// The feed store and the manifest store read again from their files,
    /// and the history opened again (its import, sweep and trim), as at a
    /// start (the test hooks' `test.swarm_world`, D11).
    #[cfg(feature = "testhooks")]
    pub fn reload(&mut self, now_ms: u64) -> (FeedStore, ManifestStore) {
        self.history.conn = None;
        let _ = self.history.conn(now_ms);
        (load_feeds(&self.root, now_ms), load_manifests(&self.root))
    }

    /// `swarm-feeds.json` replaced by `text`, or removed (`None`), and read
    /// back as at a start (the test hooks' `test.swarm_world`, D11).
    #[cfg(feature = "testhooks")]
    pub fn reset_feeds(&mut self, text: Option<&str>, now_ms: u64) -> FeedStore {
        let path = self.root.join(feeds::FILE_NAME);
        match text {
            Some(text) => {
                let _ = write_file(&path, text.as_bytes(), &fc_store::NoHooks);
            }
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
        load_feeds(&self.root, now_ms)
    }

    /// A new, empty publish history in place of the database (the test
    /// hooks' `test.swarm_world`, D11): the connection closed, the files
    /// removed, and the database opened again.
    #[cfg(feature = "testhooks")]
    pub fn reset_history(&mut self, now_ms: u64) {
        self.history.conn = None;
        for suffix in ["", "-wal", "-shm"] {
            let mut name = self.history.path.clone().into_os_string();
            name.push(suffix);
            let _ = std::fs::remove_file(name);
        }
        let _ = self.history.conn(now_ms);
    }
}

/// `publish-history.sqlite`: where it is, where its legacy import reads,
/// and its one connection once open.
struct History {
    path: PathBuf,
    import: Import,
    conn: Option<Connection>,
}

impl History {
    /// The connection, opened (with the open's import, sweep and trim) if
    /// it isn't yet.
    fn conn(&mut self, now_ms: u64) -> Result<&mut Connection, JsString> {
        match &mut self.conn {
            Some(conn) => Ok(conn),
            slot @ None => match open_history(&self.path, &self.import, now_ms) {
                Ok(conn) => Ok(slot.insert(conn)),
                Err(e) => {
                    crate::log::error(
                        "swarm: cannot open publish-history.sqlite",
                        serde_json::json!({ "error": e.to_string() }),
                    );
                    Err(JsString::from(HISTORY_FAILED))
                }
            },
        }
    }

    /// [`History::conn`] for a write, which the test hooks can fail.
    fn writable(&mut self, now_ms: u64) -> Result<&mut Connection, JsString> {
        if crate::testhooks::grant_write_fails(HISTORY_HOOKS, "write") {
            return Err(JsString::from(HISTORY_FAILED));
        }
        self.conn(now_ms)
    }
}

fn history_failed(e: rusqlite::Error) -> JsString {
    crate::log::error(
        "swarm: a publish-history.sqlite statement failed",
        serde_json::json!({ "error": e.to_string() }),
    );
    JsString::from(HISTORY_FAILED)
}

/// `getDb()`: the database with the reference's schema, then
/// `migrateFromJson`, `sweepOrphans` and the bound (`history::open`).
fn open_history(path: &Path, import: &Import, now_ms: u64) -> Result<Connection, sqlite::Error> {
    let mut conn = sqlite::open(path, &HISTORY_SCHEMA)?;
    let file = import.root.join(PUBLISH_HISTORY.file);
    let migrated = import.root.join(PUBLISH_HISTORY.migrated);
    // As `fs.existsSync` finds each: a link followed, any error absent.
    let bytes = if import.skip || std::fs::metadata(&file).is_err() {
        None
    } else if std::fs::metadata(&migrated).is_ok() {
        Some(None)
    } else {
        match read_file(&file, PUBLISH_HISTORY.max_bytes) {
            Read::Bytes(bytes) => Some(Some(bytes)),
            Read::Missing => None,
            Read::Unreadable => {
                not_imported_of(&PUBLISH_HISTORY, "unreadable");
                None
            }
        }
    };
    let legacy = match &bytes {
        None => history::Legacy::Absent,
        Some(None) => history::Legacy::AlreadyMigrated,
        Some(Some(bytes)) => history::Legacy::File(bytes),
    };
    let open = history::open(legacy, now_ms);
    match open.legacy {
        history::LegacyFile::Keep => {
            if matches!(bytes, Some(Some(_))) {
                not_imported_of(&PUBLISH_HISTORY, "refused");
            }
        }
        history::LegacyFile::Delete => {
            drop_stray_of(&PUBLISH_HISTORY, &file);
        }
        history::LegacyFile::Rename => match import_rows(&mut conn, &open.import) {
            Ok(()) => {
                crate::log::info(
                    "swarm_stores: imported publish-history.json",
                    serde_json::json!({ "imported": open.import.len() }),
                );
                let renamed = std::fs::rename(&file, &migrated)
                    .and_then(|()| fsx::sync_rename(&import.root, &migrated))
                    .is_ok();
                if !renamed {
                    crate::log::error(
                        "swarm_stores: cannot rename publish-history.json",
                        serde_json::json!({}),
                    );
                }
            }
            // The file stays, a recovery breadcrumb, as the reference
            // leaves it.
            Err(_) => not_imported_of(&PUBLISH_HISTORY, "write"),
        },
    }
    execute(&conn, &open.sweep)?;
    execute(&conn, &open.trim)?;
    Ok(conn)
}

/// The legacy entries' inserts, in one transaction (`insertMany`).
fn import_rows(conn: &mut Connection, inserts: &[Statement]) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    for insert in inserts {
        execute(&tx, insert)?;
    }
    tx.commit()
}

/// A parameter, as better-sqlite3 binds the JavaScript value.
fn sql_value(bind: &Bind) -> rusqlite::types::Value {
    use rusqlite::types::Value;
    match bind {
        Bind::Null => Value::Null,
        Bind::Integer(n) => Value::Integer(*n),
        Bind::Real(n) => Value::Real(*n),
        Bind::Text(text) => Value::Text(text.clone()),
    }
}

/// Runs `statement` with its parameters: the rows it changed.
fn execute(conn: &Connection, statement: &Statement) -> rusqlite::Result<usize> {
    conn.execute(
        statement.sql,
        rusqlite::params_from_iter(statement.params.iter().map(sql_value)),
    )
}

/// `statement`'s rows, each cell as SQLite answers it.
fn query(conn: &Connection, statement: &Statement) -> rusqlite::Result<Vec<Row>> {
    use rusqlite::types::ValueRef;
    let mut prepared = conn.prepare(statement.sql)?;
    let columns = prepared.column_count();
    let rows = prepared.query_map(
        rusqlite::params_from_iter(statement.params.iter().map(sql_value)),
        |row| {
            (0..columns)
                .map(|i| {
                    Ok(match row.get_ref(i)? {
                        ValueRef::Null => Cell::Null,
                        ValueRef::Integer(n) => Cell::Integer(n),
                        ValueRef::Real(n) => Cell::Real(n),
                        ValueRef::Text(text) => {
                            Cell::Text(String::from_utf8_lossy(text).into_owned())
                        }
                        ValueRef::Blob(bytes) => Cell::Blob(bytes.to_vec()),
                    })
                })
                .collect()
        },
    )?;
    rows.collect()
}

/// Whether a name is taken in `root`, for a backup's name: anything there,
/// a dangling link included.
fn taken(root: &Path) -> impl Fn(&str) -> bool + '_ {
    move |name| std::fs::symlink_metadata(root.join(name)).is_ok()
}

/// `loadFeeds()` over `root`'s `swarm-feeds.json` ([module docs](self)).
pub fn load_feeds(root: &Path, now_ms: u64) -> FeedStore {
    let path = root.join(feeds::FILE_NAME);
    let hooks = GrantWrite(FEEDS_HOOKS);
    let bytes = match read_file(&path, feeds::MAX_FILE_BYTES + 1) {
        Read::Missing => return FeedStore::empty(),
        Read::Bytes(bytes) => bytes,
        // Not a regular file the user owns, or past the bound by more than
        // a byte: it can't be copied, so it is renamed aside under the name
        // a file that doesn't parse is kept under.
        Read::Unreadable => {
            let name = backup_name("corrupt", taken(root));
            let aside = root.join(&name);
            let moved = std::fs::rename(&path, &aside)
                .and_then(|()| fsx::sync_rename(root, &aside))
                .is_ok();
            crate::log::error(
                "swarm: swarm-feeds.json is unreadable; kept aside, the store starts empty",
                serde_json::json!({ "moved": moved }),
            );
            return FeedStore::empty();
        }
    };
    let loaded = FeedStore::load(Some(&bytes), now_ms, taken(root));
    let mut store = loaded.store;
    for write in loaded.writes {
        match write {
            // `fs.copyFileSync(file, backup)`: the bytes read, copied.
            LoadWrite::Backup { name } => {
                let copied = write_file(&root.join(&name), &bytes, &hooks).is_ok();
                crate::log::error(
                    "swarm: swarm-feeds.json kept aside",
                    serde_json::json!({ "copied": copied }),
                );
            }
            // A migration's write that fails: the file kept aside again as
            // one that doesn't load, and the store empty.
            LoadWrite::Write(text) => {
                if write_file(&path, text.as_bytes(), &hooks).is_err() {
                    let name = backup_name("corrupt", taken(root));
                    let _ = write_file(&root.join(name), &bytes, &hooks);
                    crate::log::error(
                        "swarm: cannot write swarm-feeds.json's migration; kept aside, the store starts empty",
                        serde_json::json!({}),
                    );
                    store = FeedStore::empty();
                }
            }
        }
    }
    store
}

/// `loadStore()` over `root`'s `swarm-manifest-grants.json`, its `.bak` where
/// it isn't readable. Neither readable: the store stays unloaded, and each
/// operation fails as the reference's throws (the codec's `Unreadable`).
pub fn load_manifests(root: &Path) -> ManifestStore {
    let mut store = ManifestStore::new();
    let bound = manifests::MAX_FILE_BYTES + 1;
    let file = match read_file(&root.join(manifests::FILE_NAME), bound) {
        Read::Missing => None,
        Read::Bytes(bytes) => Some(bytes),
        // As one that doesn't parse: its backup is read.
        Read::Unreadable => Some(Vec::new()),
    };
    let backup = || match read_file(&root.join(manifests::BACKUP_NAME), bound) {
        Read::Bytes(bytes) => Some(bytes),
        Read::Missing | Read::Unreadable => None,
    };
    if store.load(file.as_deref(), backup).is_err() {
        crate::log::error(
            "swarm: swarm-manifest-grants.json and its backup are unreadable",
            serde_json::json!({}),
        );
    }
    store
}

#[cfg(test)]
mod tests;
