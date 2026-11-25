//! `publish-history.sqlite` (the reference's `swarm/publish-history.js`):
//! one row per upload, in table `publishes`.
//!
//! The crate does no I/O, so SQLite is `freedom-cored`'s (design 0015,
//! "Crates": "SQLite through `rusqlite` with the schema kept, one
//! writer"), as for `payment-history.sqlite` (design 0013, "Where SQLite
//! lives"). Here are the schema and pragmas as data ([`SCHEMA_VERSION`],
//! [`DDL`], [`JOURNAL_MODE`]), what the open does after them ([`open`]: the
//! legacy `publish-history.json`'s one-shot import, the sweep of rows left
//! `uploading` to `failed`, the bound), each operation up to the driver as
//! [`Statement`]s with the reference's SQL and its parameters bound as
//! better-sqlite3 binds JavaScript values ([`bind`]), and back from the
//! rows SQLite answers ([`Cell`]) to `rowToEntry`'s records ([`entry`]).
//! SQLite applies the columns' affinities to those values as under the
//! reference.
//!
//! The daemon opens the database as the reference does at its first
//! operation (`getDb`): `journal_mode = WAL`, the DDL and `user_version` on
//! a new database, then [`open`]'s import, sweep and bound.
//!
//! What differs from the reference:
//! - `history-bound` (design 0015): at most [`MAX_ROWS`] rows. After each
//!   insert, and at the open, [`TRIM_SQL`] deletes the oldest finished rows
//!   (`completed` or `failed`), the oldest first, then if need be the
//!   oldest others, past the bound. A row is never deleted while the table
//!   is within it.
//! - `Date.parse` of a legacy entry's `timestamp` (and of a `started_at`
//!   or `completed_at` cell that holds text, which no writer makes) reads
//!   ECMAScript's date-time format with a UTC offset or none for a date
//!   alone, as V8 does; V8's other formats, a date-time without an offset
//!   (local time: the core has no time zone) among them, are not a date,
//!   so the import takes the open's time for one, as the reference does for
//!   a string it can't parse. The browser wrote `toISOString()`'s form. The
//!   design says nothing of this.

use fc_json::{JsString, JsValue};

use super::{Thrown, or_falsy, or_nullish, text};

/// The database's name at the Freedom root.
pub const FILE_NAME: &str = "publish-history.sqlite";

/// The legacy store, at the profile's `userData` root, and its name once
/// imported (`publish-history.json.migrated`).
pub const LEGACY_FILE: &str = "publish-history.json";
pub const MIGRATED_SUFFIX: &str = ".migrated";

/// The schema's `user_version`.
pub const SCHEMA_VERSION: i32 = 1;

/// `db.pragma('journal_mode = WAL')`, at every open.
pub const JOURNAL_MODE: &str = "WAL";

/// The DDL `migrateDatabase` runs on a database below [`SCHEMA_VERSION`],
/// byte for byte: SQLite keeps each statement's text in `sqlite_master`.
pub const DDL: &str = r#"
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
    "#;

/// The table's columns in their order, which `SELECT *` answers.
pub const COLUMNS: [&str; 13] = [
    "id",
    "type",
    "name",
    "status",
    "reference",
    "bzz_url",
    "tag_uid",
    "batch_id",
    "origin",
    "bytes_size",
    "started_at",
    "completed_at",
    "error_message",
];

/// The most rows the table keeps (deviation `history-bound`).
pub const MAX_ROWS: usize = 10_000;

/// `ORPHAN_SWEEP_MESSAGE`: a row left `uploading` by a session that ended.
pub const ORPHAN_SWEEP_MESSAGE: &str = "interrupted by app exit";

/// The statements' text, as the reference prepares them.
pub const INSERT_SQL: &str = "
      INSERT INTO publishes (
        type, name, status, reference, bzz_url, tag_uid, batch_id,
        origin, bytes_size, started_at, completed_at, error_message
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ";
pub const UPDATE_SQL: &str = "
      UPDATE publishes SET
        status        = COALESCE(?, status),
        reference     = COALESCE(?, reference),
        bzz_url       = COALESCE(?, bzz_url),
        tag_uid       = COALESCE(?, tag_uid),
        batch_id      = COALESCE(?, batch_id),
        bytes_size    = COALESCE(?, bytes_size),
        completed_at  = COALESCE(?, completed_at),
        error_message = COALESCE(?, error_message)
      WHERE id = ?
    ";
pub const ALL_SQL: &str = "SELECT * FROM publishes ORDER BY started_at DESC";
pub const BY_ID_SQL: &str = "SELECT * FROM publishes WHERE id = ?";
pub const DELETE_SQL: &str = "DELETE FROM publishes WHERE id = ?";
pub const CLEAR_SQL: &str = "DELETE FROM publishes";
pub const SWEEP_SQL: &str = "
    UPDATE publishes
    SET status = ?, error_message = ?, completed_at = ?
    WHERE status = ?
  ";
/// The bound's statement (deviation `history-bound`): the rows past
/// [`MAX_ROWS`], finished ones first, each kind oldest first, never the row
/// its parameter names (the one just inserted, which a clock set back would
/// otherwise make the oldest; `NULL` at the open).
pub const TRIM_SQL: &str = "
    DELETE FROM publishes WHERE id IN (
      SELECT id FROM publishes WHERE id IS NOT ?
      ORDER BY CASE WHEN status IN ('completed', 'failed') THEN 0 ELSE 1 END,
        started_at, id
      LIMIT max((SELECT COUNT(*) FROM publishes) - 10000, 0)
    )
  ";

/// `FINAL_STATUSES`.
const FINAL_STATUSES: [&str; 2] = ["completed", "failed"];

/// A statement parameter as better-sqlite3 binds a JavaScript value: a
/// number as a double, a string as its UTF-8 (a lone surrogate as U+FFFD),
/// `null` and `undefined` as NULL.
#[derive(Debug, Clone, PartialEq)]
pub enum Bind {
    Null,
    /// A rowid the core binds itself.
    Integer(i64),
    Real(f64),
    Text(String),
}

/// A column's value as SQLite answers it.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// A row as SQLite answers it, one cell per column ([`COLUMNS`]).
pub type Row = Vec<Cell>;

/// A statement and the parameters it runs with.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub sql: &'static str,
    pub params: Vec<Bind>,
}

/// What becomes of `publish-history.json` at the open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyFile {
    /// Left where it is: there is none, or it doesn't import (a recovery
    /// breadcrumb).
    Keep,
    /// Removed: a stray copy beside its `.migrated` (an unlink that fails
    /// is only logged).
    Delete,
    /// Renamed to `publish-history.json.migrated` once its rows are
    /// committed.
    Rename,
}

/// The legacy file as the open finds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Legacy<'a> {
    /// No `publish-history.json`.
    Absent,
    /// `publish-history.json` beside its `.migrated`: imported before.
    AlreadyMigrated,
    /// `publish-history.json`'s bytes.
    File(&'a [u8]),
}

/// What the open runs after the schema, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct Open {
    /// The legacy entries' inserts, in one transaction (`insertMany`).
    pub import: Vec<Statement>,
    /// What becomes of the legacy file, after the import commits; if it
    /// doesn't, the file is kept.
    pub legacy: LegacyFile,
    /// `sweepOrphans`: every `uploading` row `failed`.
    pub sweep: Statement,
    /// The bound.
    pub trim: Statement,
}

/// `getDb()`'s work after the schema: `migrateFromJson` and `sweepOrphans`,
/// then the bound, at `now_ms`.
pub fn open(legacy: Legacy<'_>, now_ms: u64) -> Open {
    let (import, legacy) = match legacy {
        Legacy::Absent => (Vec::new(), LegacyFile::Keep),
        Legacy::AlreadyMigrated => (Vec::new(), LegacyFile::Delete),
        Legacy::File(bytes) => match import(bytes, now_ms) {
            Some(statements) => (statements, LegacyFile::Rename),
            None => (Vec::new(), LegacyFile::Keep),
        },
    };
    Open {
        import,
        legacy,
        sweep: sweep(now_ms),
        trim: trim(None),
    }
}

/// The legacy file's inserts, or `None` where the reference's import throws
/// (the file isn't JSON, an entry can't be read or bound): nothing is
/// imported then, and the file stays.
fn import(bytes: &[u8], now_ms: u64) -> Option<Vec<Statement>> {
    let raw = super::parse_file(bytes)?;
    let entries = match raw.get("entries") {
        Some(JsValue::Array(entries)) => entries.as_slice(),
        _ => &[],
    };
    entries
        .iter()
        .map(|e| import_entry(e, now_ms).ok())
        .collect()
}

/// One legacy entry's insert.
fn import_entry(e: &JsValue, now_ms: u64) -> Result<Statement, Thrown> {
    let timestamp = prop(e, "timestamp")?;
    let parsed = if timestamp.truthy() {
        date_parse(&super::property_key(timestamp)?)
    } else {
        f64::NAN
    };
    let started_at = if parsed.is_finite() {
        JsValue::Number(parsed)
    } else {
        super::time(now_ms)
    };
    let status = or_falsy(Some(prop(e, "status")?), text("completed"));
    let completed_at = if is_final(&status) {
        started_at.clone()
    } else {
        JsValue::Null
    };
    let args = [
        or_falsy(Some(prop(e, "type")?), text("data")),
        or_falsy(Some(prop(e, "name")?), JsValue::Null),
        status,
        or_falsy(Some(prop(e, "reference")?), JsValue::Null),
        or_falsy(Some(prop(e, "bzzUrl")?), JsValue::Null),
        or_nullish(Some(prop(e, "tagUid")?), JsValue::Null),
        or_falsy(Some(prop(e, "batchIdUsed")?), JsValue::Null),
        JsValue::Null,
        JsValue::Null,
        started_at,
        completed_at,
        JsValue::Null,
    ];
    statement(INSERT_SQL, &args, 12)
}

/// `sweepOrphans`' statement.
pub fn sweep(now_ms: u64) -> Statement {
    Statement {
        sql: SWEEP_SQL,
        params: vec![
            Bind::Text("failed".to_owned()),
            Bind::Text(ORPHAN_SWEEP_MESSAGE.to_owned()),
            real(now_ms),
            Bind::Text("uploading".to_owned()),
        ],
    }
}

/// The bound's statement, after each insert (keeping the inserted row,
/// `keep`) and at the open (`None`).
pub fn trim(keep: Option<i64>) -> Statement {
    Statement {
        sql: TRIM_SQL,
        params: vec![keep.map_or(Bind::Null, Bind::Integer)],
    }
}

/// `addEntry(entry)`'s read before its first `getDb()` (the open): `entry.
/// status`, which throws on a `null` entry, so that refusal opens nothing.
/// `entry` is `undefined` when absent (the default `{}`).
pub fn add_entry_checks(entry: &JsValue) -> Result<(), Thrown> {
    prop(entry, "status").map(drop)
}

/// `addEntry(entry)` up to its insert: the type and status defaulted
/// (`data`, `uploading`), `completed_at` stamped for a final status. The
/// caller runs [`trim`] after it with the new rowid, which the bound keeps,
/// then reads the row back by that rowid ([`by_rowid`]) for [`entry`].
pub fn add_entry(entry: &JsValue, now_ms: u64) -> Result<Statement, Thrown> {
    let status = or_falsy(Some(prop(entry, "status")?), text("uploading"));
    let started_at = super::time(now_ms);
    let completed_at = if is_final(&status) {
        started_at.clone()
    } else {
        JsValue::Null
    };
    let args = [
        or_falsy(Some(prop(entry, "type")?), text("data")),
        or_falsy(Some(prop(entry, "name")?), JsValue::Null),
        status,
        or_falsy(Some(prop(entry, "reference")?), JsValue::Null),
        or_falsy(Some(prop(entry, "bzzUrl")?), JsValue::Null),
        or_nullish(Some(prop(entry, "tagUid")?), JsValue::Null),
        or_falsy(Some(prop(entry, "batchIdUsed")?), JsValue::Null),
        or_falsy(Some(prop(entry, "origin")?), JsValue::Null),
        or_nullish(Some(prop(entry, "bytesSize")?), JsValue::Null),
        started_at,
        completed_at,
        or_falsy(Some(prop(entry, "errorMessage")?), JsValue::Null),
    ];
    statement(INSERT_SQL, &args, 12)
}

/// The row an insert made (`getById.get(result.lastInsertRowid)`).
pub fn by_rowid(rowid: i64) -> Statement {
    #[expect(
        clippy::cast_precision_loss,
        reason = "better-sqlite3 answers lastInsertRowid as a JavaScript number"
    )]
    let id = Bind::Real(rowid as f64);
    Statement {
        sql: BY_ID_SQL,
        params: vec![id],
    }
}

/// `updateEntry(id, updates)`'s read before its first `getDb()`:
/// `updates.status`, which throws on `null`. `updates` is `undefined` when
/// absent (the default `{}`).
pub fn update_entry_checks(updates: &JsValue) -> Result<(), Thrown> {
    prop(updates, "status").map(drop)
}

/// `updateEntry(id, updates)` up to its update: each field kept where
/// `updates` gives none (`COALESCE`), `completed_at` stamped for a final
/// status. With no row changed the answer is `null`; otherwise the caller
/// reads the row back ([`by_id`]) for [`entry`].
pub fn update_entry(id: &JsValue, updates: &JsValue, now_ms: u64) -> Result<Statement, Thrown> {
    let status = or_falsy(Some(prop(updates, "status")?), JsValue::Null);
    let completed_at = if is_final(&status) {
        super::time(now_ms)
    } else {
        JsValue::Null
    };
    let args = [
        status,
        or_falsy(Some(prop(updates, "reference")?), JsValue::Null),
        or_falsy(Some(prop(updates, "bzzUrl")?), JsValue::Null),
        or_nullish(Some(prop(updates, "tagUid")?), JsValue::Null),
        or_falsy(Some(prop(updates, "batchIdUsed")?), JsValue::Null),
        or_nullish(Some(prop(updates, "bytesSize")?), JsValue::Null),
        completed_at,
        or_falsy(Some(prop(updates, "errorMessage")?), JsValue::Null),
        id.clone(),
    ];
    statement(UPDATE_SQL, &args, 9)
}

/// `getById.get(id)`.
pub fn by_id(id: &JsValue) -> Result<Statement, Thrown> {
    statement(BY_ID_SQL, std::slice::from_ref(id), 1)
}

/// `getEntries()`'s statement: every row, the latest first.
pub fn get_entries() -> Statement {
    Statement {
        sql: ALL_SQL,
        params: Vec::new(),
    }
}

/// `removeEntry(id)`'s statement: the answer is whether it deleted a row.
pub fn remove_entry(id: &JsValue) -> Result<Statement, Thrown> {
    statement(DELETE_SQL, std::slice::from_ref(id), 1)
}

/// `clearEntries()`'s statement: the answer is `undefined`.
pub fn clear_entries() -> Statement {
    Statement {
        sql: CLEAR_SQL,
        params: Vec::new(),
    }
}

/// Why a row isn't a record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RowError {
    /// The reference's own throw: a time `new Date(…).toISOString()`
    /// refuses (`RangeError: Invalid time value`).
    #[error(transparent)]
    Thrown(Thrown),
    /// A BLOB cell, which the reference would answer as a `Buffer` and no
    /// JSON answer holds (deviation `history-blobs`): the read fails, as a
    /// bad timestamp's does. No statement here writes one.
    #[error("column {0} holds a BLOB")]
    Blob(&'static str),
    /// Fewer cells than columns.
    #[error("the row has {0} cells")]
    Short(usize),
}

/// `rowToEntry(row)`.
pub fn entry(row: &[Cell]) -> Result<JsValue, RowError> {
    if row.len() < COLUMNS.len() {
        return Err(RowError::Short(row.len()));
    }
    let value = |index: usize| -> Result<JsValue, RowError> {
        Ok(match &row[index] {
            Cell::Null => JsValue::Null,
            #[expect(
                clippy::cast_precision_loss,
                reason = "better-sqlite3 reads an INTEGER as the nearest double"
            )]
            Cell::Integer(n) => JsValue::Number(*n as f64),
            Cell::Real(n) => JsValue::Number(*n),
            Cell::Text(t) => text(t),
            Cell::Blob(_) => return Err(RowError::Blob(COLUMNS[index])),
        })
    };
    let completed = value(11)?;
    let mut out = JsValue::Object(Vec::new());
    out.set("id", value(0)?);
    out.set("type", value(1)?);
    out.set("name", value(2)?);
    out.set("status", value(3)?);
    out.set("reference", value(4)?);
    out.set("bzzUrl", value(5)?);
    out.set("tagUid", value(6)?);
    out.set("batchIdUsed", value(7)?);
    out.set("origin", value(8)?);
    out.set("bytesSize", value(9)?);
    out.set("timestamp", text(&iso_of(&value(10)?)?));
    out.set(
        "completedAt",
        if completed.truthy() {
            text(&iso_of(&completed)?)
        } else {
            JsValue::Null
        },
    );
    out.set("errorMessage", value(12)?);
    Ok(out)
}

/// `getEntries()`'s answer over [`get_entries`]'s rows: each row's record,
/// or the first row's refusal, which fails the whole read as the
/// reference's throw does (a bad timestamp; a BLOB cell, `history-blobs`).
pub fn entries(rows: &[Vec<Cell>]) -> Result<JsValue, RowError> {
    rows.iter()
        .map(|row| entry(row))
        .collect::<Result<Vec<_>, _>>()
        .map(JsValue::Array)
}

/// `new Date(value).toISOString()` for a cell's value.
fn iso_of(value: &JsValue) -> Result<String, RowError> {
    let ms = match value {
        JsValue::Null => 0.0,
        JsValue::Number(n) => *n,
        JsValue::String(s) => date_parse(s),
        _ => f64::NAN,
    };
    iso_string(ms).ok_or_else(|| RowError::Thrown(Thrown::range_error("Invalid time value")))
}

/// `isFinalStatus(status)`.
fn is_final(status: &JsValue) -> bool {
    matches!(status, JsValue::String(s) if FINAL_STATUSES.iter().any(|f| s == *f))
}

fn real(ms: u64) -> Bind {
    #[expect(
        clippy::cast_precision_loss,
        reason = "Date.now() is a double; times below 2^53 ms are exact"
    )]
    let ms = ms as f64;
    Bind::Real(ms)
}

// Statics, not consts: `JsValue` has a `Drop`, so a const's reference isn't
// promoted to `'static`.
static UNDEFINED: JsValue = JsValue::Undefined;

/// `value[name]`: `undefined` where absent or on a primitive (none of the
/// names is on a primitive's prototype), V8's `TypeError` on `null` or
/// `undefined`. A parameter's default (`{}`) is applied by the caller:
/// `undefined` reads as it.
fn prop<'v>(value: &'v JsValue, name: &str) -> Result<&'v JsValue, Thrown> {
    match value {
        JsValue::Undefined => Ok(&UNDEFINED),
        JsValue::Null => Err(Thrown::type_error(format!(
            "Cannot read properties of null (reading '{name}')"
        ))),
        JsValue::Object(_) => Ok(value.get(name).unwrap_or(&UNDEFINED)),
        _ => Ok(&UNDEFINED),
    }
}

/// Binds a `run` or `get` call's arguments on a statement with `count`
/// anonymous parameters, as better-sqlite3's `Binder` does: an array's
/// items bind one parameter each; a plain object binds named parameters,
/// of which these statements have none, so it binds nothing, and a second
/// one is refused; anything else binds one parameter. A boolean, or an
/// array or object inside an array, can't be bound.
pub fn bind(args: &[JsValue], count: usize) -> Result<Vec<Bind>, Thrown> {
    let mut out = Vec::with_capacity(count);
    let mut bound_object = false;
    for arg in args {
        match arg {
            JsValue::Array(items) => {
                for item in items {
                    bind_one(item, count, &mut out)?;
                }
            }
            JsValue::Object(_) => {
                if bound_object {
                    return Err(Thrown::type_error(
                        "You cannot specify named parameters in two different objects",
                    ));
                }
                bound_object = true;
            }
            other => bind_one(other, count, &mut out)?,
        }
    }
    if out.len() < count {
        return Err(Thrown::range_error(
            "Too few parameter values were provided",
        ));
    }
    Ok(out)
}

fn bind_one(value: &JsValue, count: usize, out: &mut Vec<Bind>) -> Result<(), Thrown> {
    let bound = match value {
        JsValue::Undefined | JsValue::Null => Bind::Null,
        JsValue::Number(n) => Bind::Real(*n),
        JsValue::String(s) => Bind::Text(s.as_str().to_owned()),
        JsValue::Bool(_) | JsValue::Array(_) | JsValue::Object(_) => {
            return Err(Thrown::type_error(
                "SQLite3 can only bind numbers, strings, bigints, buffers, and null",
            ));
        }
    };
    if out.len() >= count {
        return Err(Thrown::range_error(
            "Too many parameter values were provided",
        ));
    }
    out.push(bound);
    Ok(())
}

fn statement(sql: &'static str, args: &[JsValue], count: usize) -> Result<Statement, Thrown> {
    Ok(Statement {
        sql,
        params: bind(args, count)?,
    })
}

// --- dates -------------------------------------------------------------------------

/// The largest time value a `Date` holds, in milliseconds either side of
/// the epoch.
const MAX_TIME_MS: f64 = 8_640_000_000_000_000.0;

/// `new Date(ms).toISOString()` (after `TimeClip`), or `None` where it
/// throws (`RangeError: Invalid time value`).
fn iso_string(ms: f64) -> Option<String> {
    if !ms.is_finite() || ms.abs() > MAX_TIME_MS {
        return None;
    }
    // TimeClip: toward zero.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a finite time within ±8.64e15, truncated as TimeClip does"
    )]
    let ms = ms.trunc() as i64;
    let days = ms.div_euclid(86_400_000);
    let in_day = ms.rem_euclid(86_400_000);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    Some(format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        in_day / 3_600_000,
        in_day / 60_000 % 60,
        in_day / 1000 % 60,
        in_day % 1000
    ))
}

/// Howard Hinnant's days_from_civil, `month` 1–12.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `Date.parse(text)` for ECMAScript's date-time string format as V8 reads
/// it: `YYYY`, `YYYY-MM` or `YYYY-MM-DD` (or a signed six-digit year), as
/// UTC; or with `THH:mm`, `:ss` and a fraction of any length (`T` and `Z`
/// in either case), and `Z` or an offset `±HH:mm` or `±HHmm`. A day up to
/// 31 runs into the next month, as V8's does; hour 24 only at `24:00`.
/// `NaN` for anything else (module docs).
pub fn date_parse(text: &JsString) -> f64 {
    parse_iso(text.as_str()).unwrap_or(f64::NAN)
}

fn parse_iso(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let digits = |i: &mut usize, n: usize| -> Option<i64> {
        let part = b.get(*i..*i + n)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        *i += n;
        part.iter().try_fold(0i64, |acc, d| {
            acc.checked_mul(10)?.checked_add(i64::from(d - b'0'))
        })
    };
    let year = match b.first()? {
        sign @ (b'+' | b'-') => {
            i += 1;
            let y = digits(&mut i, 6)?;
            if *sign == b'-' {
                if y == 0 {
                    return None;
                }
                -y
            } else {
                y
            }
        }
        _ => digits(&mut i, 4)?,
    };
    let (mut month, mut day) = (1, 1);
    if b.get(i) == Some(&b'-') {
        i += 1;
        month = digits(&mut i, 2)?;
        if b.get(i) == Some(&b'-') {
            i += 1;
            day = digits(&mut i, 2)?;
        }
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut ms = days_from_civil(year, month, 1).checked_add(day - 1)? as f64 * 86_400_000.0;
    if i == b.len() {
        return within(ms);
    }
    if !matches!(b.get(i), Some(b'T' | b't')) {
        return None;
    }
    i += 1;
    let hour = digits(&mut i, 2)?;
    if b.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    let minute = digits(&mut i, 2)?;
    let (mut second, mut millis) = (0, 0);
    if b.get(i) == Some(&b':') {
        i += 1;
        second = digits(&mut i, 2)?;
        if b.get(i) == Some(&b'.') {
            i += 1;
            let start = i;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            if i == start {
                return None;
            }
            let frac = &s[start..i];
            let first3: String = frac.chars().chain("00".chars()).take(3).collect();
            millis = first3.parse().ok()?;
        }
    }
    if hour > 24 || minute > 59 || second > 59 {
        return None;
    }
    if hour == 24 && (minute != 0 || second != 0 || millis != 0) {
        return None;
    }
    let offset = match b.get(i) {
        Some(b'Z' | b'z') => {
            i += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            let sign = if *sign == b'-' { -1 } else { 1 };
            i += 1;
            let oh = digits(&mut i, 2)?;
            if b.get(i) == Some(&b':') {
                i += 1;
            }
            let om = digits(&mut i, 2)?;
            if oh > 23 || om > 59 {
                return None;
            }
            sign * (oh * 3_600_000 + om * 60_000)
        }
        // A date-time without an offset is local time.
        _ => return None,
    };
    if i != b.len() {
        return None;
    }
    ms += (hour * 3_600_000 + minute * 60_000 + second * 1000 + millis - offset) as f64;
    within(ms)
}

fn within(ms: f64) -> Option<f64> {
    (ms.abs() <= MAX_TIME_MS).then_some(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> f64 {
        date_parse(&JsString::from(text))
    }

    #[test]
    fn dates_as_v8_parses_them() {
        // Node 22, TZ=UTC: Date.parse(text).
        let cases: &[(&str, f64)] = &[
            ("2025-06-01T10:00:00.000Z", 1748772000000.0),
            ("2025-06-01", 1748736000000.0),
            ("2025-06", 1748736000000.0),
            ("2025", 1735689600000.0),
            ("+002025-06-01T00:00:00Z", 1748736000000.0),
            ("-000001-01-01T00:00:00Z", -62198755200000.0),
            ("2025-06-01T10:00Z", 1748772000000.0),
            ("2025-06-01T10:00:00.1Z", 1748772000100.0),
            ("2025-06-01T10:00:00.123456Z", 1748772000123.0),
            ("2025-06-01t10:00:00z", 1748772000000.0),
            ("2025-02-30", 1740873600000.0),
            ("2025-06-31", 1751328000000.0),
            ("2025-06-01T24:00:00Z", 1748822400000.0),
            ("2025-06-01T10:00:00+02:00", 1748764800000.0),
            ("2025-06-01T10:00:00+0200", 1748764800000.0),
            ("2025-06-01T10:00:00.000+23:59", 1748685660000.0),
            ("+275760-09-13T00:00:00.000Z", 8640000000000000.0),
        ];
        for (text, want) in cases {
            assert_eq!(parse(text), *want, "{text}");
        }
        for text in [
            "-000000-01-01T00:00:00Z",
            "2025-06-01T24:00:01Z",
            "2025-13-01",
            "not a date",
            "2025-06-01T10:00:00.Z",
            "2025-06-01T10Z",
            "2025-06-01T10:00:60Z",
            "275760-09-13T00:00:00Z",
            "+275760-09-13T00:00:00.001Z",
            "2025-06-01T10:00:00.000+24:00",
            // Local time, and V8's legacy forms: not read here.
            "2025-06-01T10:00:00",
            "5",
            " 2025-06-01",
        ] {
            assert!(parse(text).is_nan(), "{text}");
        }
    }

    #[test]
    fn times_as_to_iso_string_writes_them() {
        assert_eq!(iso_string(1.9).as_deref(), Some("1970-01-01T00:00:00.001Z"));
        assert_eq!(
            iso_string(-1.9).as_deref(),
            Some("1969-12-31T23:59:59.999Z")
        );
        assert_eq!(
            iso_string(MAX_TIME_MS).as_deref(),
            Some("+275760-09-13T00:00:00.000Z")
        );
        assert_eq!(iso_string(MAX_TIME_MS + 1.0), None);
        assert_eq!(iso_string(f64::NAN), None);
    }

    #[test]
    fn the_bound_names_max_rows() {
        assert!(TRIM_SQL.contains(&format!("- {MAX_ROWS},")));
    }

    #[test]
    fn values_bind_as_better_sqlite3_binds_them() {
        let js = |text: &str| fc_json::parse(text).unwrap();
        assert_eq!(
            add_entry(&js("{\"name\":true}"), 1),
            Err(Thrown::type_error(
                "SQLite3 can only bind numbers, strings, bigints, buffers, and null"
            ))
        );
        assert_eq!(
            add_entry(&js("{\"name\":{\"a\":1}}"), 1),
            Err(Thrown::range_error(
                "Too few parameter values were provided"
            ))
        );
        assert_eq!(
            add_entry(&js("{\"name\":[1,2]}"), 1),
            Err(Thrown::range_error(
                "Too many parameter values were provided"
            ))
        );
        assert_eq!(
            add_entry_checks(&JsValue::Null),
            Err(Thrown::type_error(
                "Cannot read properties of null (reading 'status')"
            ))
        );
        let insert = add_entry(&JsValue::Undefined, 7).unwrap();
        assert_eq!(insert.params[0], Bind::Text("data".into()));
        assert_eq!(insert.params[2], Bind::Text("uploading".into()));
        assert_eq!(insert.params[9], Bind::Real(7.0));
        assert_eq!(insert.params[10], Bind::Null);
    }

    #[test]
    fn rows_read_as_row_to_entry_reads_them() {
        let mut row: Row = vec![
            Cell::Integer(1),
            Cell::Text("data".into()),
            Cell::Null,
            Cell::Text("completed".into()),
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Integer(0),
            Cell::Integer(0),
            Cell::Null,
        ];
        let entry_of = |row: &Row| entry(row).unwrap();
        let record = entry_of(&row);
        assert_eq!(
            record.get("timestamp").and_then(JsValue::as_str),
            Some("1970-01-01T00:00:00.000Z")
        );
        // A completed_at of 0 is falsy: null.
        assert_eq!(record.get("completedAt"), Some(&JsValue::Null));
        row[10] = Cell::Real(f64::INFINITY);
        assert_eq!(
            entry(&row),
            Err(RowError::Thrown(Thrown::range_error("Invalid time value")))
        );
        row[10] = Cell::Blob(vec![1]);
        assert_eq!(entry(&row), Err(RowError::Blob("started_at")));
    }

    #[test]
    fn a_legacy_file_that_doesnt_import_stays() {
        assert_eq!(open(Legacy::File(b"{"), 1).legacy, LegacyFile::Keep);
        // An entry that throws (a null one) imports nothing.
        let opened = open(Legacy::File(b"{\"entries\":[{},null]}"), 1);
        assert_eq!((opened.import.len(), opened.legacy), (0, LegacyFile::Keep));
        let opened = open(Legacy::File(b"{\"entries\":[]}"), 1);
        assert_eq!(
            (opened.import.len(), opened.legacy),
            (0, LegacyFile::Rename)
        );
        let opened = open(Legacy::File(b"[1]"), 1);
        assert_eq!(
            (opened.import.len(), opened.legacy),
            (0, LegacyFile::Rename)
        );
        assert_eq!(open(Legacy::AlreadyMigrated, 1).legacy, LegacyFile::Delete);
    }
}
