//! `payment-history.sqlite`'s operations (design 0013, "Payment history"):
//! `fc_wallet_state::payments`' statements, run on the one connection
//! [`sqlite::open`] gives, and their rows read back as SQLite answers them.
//! Each operation is one of payment-history.js's functions; a write and its
//! read-back run in one immediate transaction, so `mark_dropped`'s and
//! `set_dropped_seen`'s check of the row and their write see no other
//! writer between them. A refusal ([`Thrown`]) comes before any statement
//! runs, as in the reference, whose checks and binder throw before its
//! driver steps.
//!
//! [`Store`] serves the `payments.*` methods: `not_moved` until
//! `core.hello` names `payments` in `store_moved`, and the database opened
//! only after that, at the first request (0013, "One writer per store").
//! That first open runs the one-shot import of `x402-receipts.json`
//! ([`Store::import`]).

use std::fmt;
use std::path::{Path, PathBuf};

use fc_json::JsValue;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_store::file::{Read, read_file};
use fc_store::fsx;
use fc_wallet_state::payments::{self as codec, Bind, Cell, Row, Statement, Thrown};
use rusqlite::types::{ToSqlOutput, Value, ValueRef};
use rusqlite::{Connection, ToSql, Transaction, TransactionBehavior};

use serde_json::value::RawValue;

use crate::sqlite::{self, Schema};

/// `payment-history.sqlite`'s schema, the reference's.
pub const SCHEMA: Schema = Schema {
    version: codec::SCHEMA_VERSION,
    ddl: codec::DDL,
};

#[derive(Debug)]
pub enum Error {
    /// The reference throws this, before anything is written.
    Thrown(Thrown),
    /// A row holds a BLOB, which no statement here writes and no JSON
    /// answer holds.
    Blob,
    Sqlite(rusqlite::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Thrown(thrown) => write!(f, "{thrown}"),
            Error::Blob => f.write_str("a payment row holds a blob"),
            Error::Sqlite(e) => write!(f, "{e}"),
        }
    }
}

impl From<Thrown> for Error {
    fn from(thrown: Thrown) -> Self {
        Error::Thrown(thrown)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

/// A bound value, as rusqlite takes it: the same SQLite type the reference's
/// driver binds.
struct Param<'a>(&'a Bind);

impl ToSql for Param<'_> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self.0 {
            Bind::Null => ToSqlOutput::Owned(Value::Null),
            Bind::Real(n) => ToSqlOutput::Owned(Value::Real(*n)),
            Bind::Text(text) => ToSqlOutput::Borrowed(ValueRef::Text(text.as_bytes())),
        })
    }
}

fn cell(value: ValueRef<'_>) -> Cell {
    match value {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(n) => Cell::Integer(n),
        ValueRef::Real(n) => Cell::Real(n),
        // V8 reads invalid UTF-8 with U+FFFD, as this does.
        ValueRef::Text(bytes) => Cell::Text(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Cell::Blob(bytes.to_vec()),
    }
}

/// Every row a statement answers, each column as SQLite holds it.
fn rows(conn: &Connection, statement: &Statement) -> Result<Vec<Row>, Error> {
    let mut prepared = conn.prepare(&statement.sql)?;
    let columns = prepared.column_count();
    let mut found = prepared.query(rusqlite::params_from_iter(
        statement.params.iter().map(Param),
    ))?;
    let mut out = Vec::new();
    while let Some(row) = found.next()? {
        let mut cells = Vec::with_capacity(columns);
        for index in 0..columns {
            cells.push(cell(row.get_ref(index)?));
        }
        out.push(cells);
    }
    Ok(out)
}

/// The rows a statement changed.
fn run(conn: &Connection, statement: &Statement) -> Result<usize, Error> {
    let mut prepared = conn.prepare(&statement.sql)?;
    Ok(prepared.execute(rusqlite::params_from_iter(
        statement.params.iter().map(Param),
    ))?)
}

fn record(row: &Row) -> Result<JsValue, Error> {
    codec::record(row).ok_or(Error::Blob)
}

/// `rowToEntry(getById.get(id))`: the record, or `null`.
fn by_id(conn: &Connection, id: &JsValue) -> Result<JsValue, Error> {
    match rows(conn, &codec::by_id(id)?)?.first() {
        Some(row) => record(row),
        None => Ok(JsValue::Null),
    }
}

/// The row by `id`, as SQLite holds it.
fn row_by_id(conn: &Connection, id: &JsValue) -> Result<Option<Row>, Error> {
    Ok(rows(conn, &codec::by_id(id)?)?.into_iter().next())
}

/// `update(id, patch)`: `null` when no row changed, the row read back by
/// `id` otherwise.
fn update_in(
    tx: &Transaction<'_>,
    id: &JsValue,
    patch: &JsValue,
    now_ms: f64,
) -> Result<JsValue, Error> {
    let statement = codec::update(id, patch, now_ms)?;
    if run(tx, &statement)? == 0 {
        return Ok(JsValue::Null);
    }
    by_id(tx, id)
}

/// One `payment-history.sqlite`, through its one connection.
pub struct Payments {
    conn: Connection,
}

impl Payments {
    pub fn new(conn: Connection) -> Self {
        Payments { conn }
    }

    fn write<T>(
        &mut self,
        f: impl FnOnce(&Transaction<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// `append(entry)`: the record inserted.
    pub fn append(&mut self, entry: &JsValue, now_ms: f64) -> Result<JsValue, Error> {
        let statement = codec::append(entry, now_ms)?;
        self.write(|tx| {
            run(tx, &statement)?;
            #[expect(
                clippy::cast_precision_loss,
                reason = "better-sqlite3's lastInsertRowid, a JS number"
            )]
            let rowid = JsValue::Number(tx.last_insert_rowid() as f64);
            by_id(tx, &rowid)
        })
    }

    /// `update(id, patch)`.
    pub fn update(&mut self, id: &JsValue, patch: &JsValue, now_ms: f64) -> Result<JsValue, Error> {
        codec::update(id, patch, now_ms)?;
        self.write(|tx| update_in(tx, id, patch, now_ms))
    }

    /// `markConfirmed(id, receipt)`.
    pub fn mark_confirmed(
        &mut self,
        id: &JsValue,
        receipt: &JsValue,
        now_ms: f64,
    ) -> Result<JsValue, Error> {
        let patch = codec::confirmed_patch(receipt)?;
        self.update(id, &patch, now_ms)
    }

    /// `markFailed(id, info)`.
    pub fn mark_failed(
        &mut self,
        id: &JsValue,
        info: &JsValue,
        now_ms: f64,
    ) -> Result<JsValue, Error> {
        let patch = codec::failed_patch(info)?;
        self.update(id, &patch, now_ms)
    }

    /// `markDropped(id)`: only a row still pending, read and written in one
    /// transaction.
    pub fn mark_dropped(&mut self, id: &JsValue, now_ms: f64) -> Result<JsValue, Error> {
        codec::by_id(id)?;
        self.write(|tx| {
            let existing = row_by_id(tx, id)?;
            if existing
                .as_ref()
                .is_some_and(|row| codec::record(row).is_none())
            {
                return Err(Error::Blob);
            }
            match codec::dropped_patch(existing.as_ref()) {
                Some(patch) => update_in(tx, id, &patch, now_ms),
                None => Ok(JsValue::Null),
            }
        })
    }

    /// The repoll's write (`setDroppedSeenAt`): only a row still pending,
    /// read and written in one transaction. The record written, or `null`
    /// when nothing was.
    pub fn set_dropped_seen(
        &mut self,
        id: &JsValue,
        seen_at: &JsValue,
        now_ms: f64,
    ) -> Result<JsValue, Error> {
        codec::by_id(id)?;
        self.write(|tx| {
            let current = row_by_id(tx, id)?;
            match codec::dropped_seen_patch(current.as_ref(), seen_at) {
                Some(patch) => update_in(tx, id, &patch, now_ms),
                None => Ok(JsValue::Null),
            }
        })
    }

    /// The repoll's read: every pending row, oldest first.
    pub fn pending(&mut self) -> Result<Vec<Row>, Error> {
        rows(&self.conn, &codec::pending())
    }

    /// `getRecent(filters)`.
    pub fn get_recent(&mut self, filters: &JsValue) -> Result<Vec<JsValue>, Error> {
        rows(&self.conn, &codec::get_recent(filters)?)?
            .iter()
            .map(record)
            .collect()
    }

    /// `getById(id)`.
    pub fn get_by_id(&mut self, id: &JsValue) -> Result<JsValue, Error> {
        by_id(&self.conn, id)
    }

    /// `getCount(filters)`.
    pub fn get_count(&mut self, filters: &JsValue) -> Result<JsValue, Error> {
        let found = rows(&self.conn, &codec::get_count(filters)?)?;
        let count = found
            .first()
            .and_then(|row| row.first())
            .and_then(Cell::to_js);
        Ok(count.unwrap_or(JsValue::Number(0.0)))
    }

    /// `clear()`: the rows deleted.
    pub fn clear(&mut self) -> Result<usize, Error> {
        self.write(|tx| run(tx, &codec::clear()))
    }

    /// The import's rows (`migrateFromJson`, inside its file checks): each
    /// entry of `text` not imported already, in one transaction. A refusal
    /// imports nothing, and the caller then leaves the file in place.
    pub fn import_legacy(&mut self, text: &str, now_ms: f64) -> Result<usize, Error> {
        let entries = codec::legacy_entries(text)?;
        if entries.is_empty() {
            return Ok(0);
        }
        self.write(|tx| {
            let mut imported = 0;
            for entry in &entries {
                let legacy = codec::legacy_row(entry, now_ms)?;
                if rows(tx, &codec::legacy_rows())?
                    .iter()
                    .any(|row| legacy.imported_as(row))
                {
                    continue;
                }
                run(tx, &legacy.insert())?;
                imported += 1;
            }
            Ok(imported)
        })
    }
}

/// The `payments.*` methods (design 0013, "Payment history"), all answered
/// at once on the vault's thread.
pub const METHODS: &[&str] = &[
    "payments.append",
    "payments.update",
    "payments.mark_confirmed",
    "payments.mark_failed",
    "payments.mark_dropped",
    "payments.set_dropped_seen",
    "payments.pending",
    "payments.get_recent",
    "payments.get_by_id",
    "payments.get_count",
    "payments.clear",
];

/// The database, at the Freedom root (`getFreedomDataPath`).
pub const DB_FILE: &str = "payment-history.sqlite";
/// The legacy receipts, at the profile's `userData` root
/// (`app.getPath('userData')`): before PRF-9, the hello's `grant_root`.
pub const LEGACY_FILE: &str = "x402-receipts.json";
/// The legacy file's name once imported.
pub const MIGRATED_FILE: &str = "x402-receipts.json.migrated";
/// The most of `x402-receipts.json` the import reads (`source: design`,
/// deviation `payments-import-bound`): the legacy store kept at most 1,000
/// receipts, so this leaves 16 KiB for each. A larger file is left in
/// place, unread, and the database serves without it.
pub const MAX_LEGACY_BYTES: usize = 16 << 20;

/// What the import did at the database's first open.
#[derive(Debug, PartialEq, Eq)]
pub enum Legacy {
    /// No `x402-receipts.json`.
    Absent,
    /// A `.migrated` was there already: the stray file was removed, or the
    /// removal failed (`false`), as the reference logs it.
    Stray(bool),
    /// Its rows were imported (this many new), in one transaction, and the
    /// file renamed `.migrated`, or the rename failed (`false`): the next
    /// start imports it again, finding every row already there.
    Imported(usize, bool),
    /// Left in place, nothing imported: unreadable (not a regular file the
    /// user owns, or past [`MAX_LEGACY_BYTES`]), refused as the reference
    /// refuses it, or its rows' write failed.
    Kept,
}

/// `payment-history.sqlite` for the methods: where it is once named, and
/// its one connection once opened.
#[derive(Default)]
pub struct Store {
    /// Set by `core.hello` naming `payments`: the root of the database and
    /// of `x402-receipts.json`. `None`: every method answers `not_moved`.
    root: Option<PathBuf>,
    open: Option<Payments>,
}

impl Store {
    pub fn new() -> Self {
        Store::default()
    }

    /// The hello named `payments`: the core serves the methods, with the
    /// database under `root`. Nothing is opened yet.
    pub fn configure(&mut self, root: PathBuf) {
        self.root = Some(root);
    }

    /// A `payments.*` request: its result, as JSON text.
    pub fn request(
        &mut self,
        method: &str,
        raw: Option<&str>,
        now_ms: u64,
    ) -> Result<Box<RawValue>, ErrorBody> {
        if !METHODS.contains(&method) {
            return Err(ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"));
        }
        let Some(root) = &self.root else {
            return Err(ErrorBody::new(
                ErrorCode::NotMoved,
                "main still writes the payment history (payments isn't in store_moved)",
            )
            .with_data(serde_json::json!({ "store": "payments" })));
        };
        let params = match raw {
            None => JsValue::Object(Vec::new()),
            Some(text) => fc_json::parse(text).map_err(|_| invalid())?,
        };
        if !matches!(params, JsValue::Object(_)) {
            return Err(invalid());
        }
        const UNDEFINED: &JsValue = &JsValue::Undefined;
        let arg = |name: &str| params.get(name).unwrap_or(UNDEFINED);
        #[expect(
            clippy::cast_precision_loss,
            reason = "Date.now(), a JS number of milliseconds"
        )]
        let now = now_ms as f64;
        let payments = match &mut self.open {
            Some(payments) => payments,
            None => {
                let mut payments =
                    Payments::new(sqlite::open(&root.join(DB_FILE), &SCHEMA).map_err(open_failed)?);
                Store::import(root, &mut payments, now);
                self.open.insert(payments)
            }
        };
        let answer = |key: &str, value: &JsValue| format!("{{\"{key}\":{}}}", value.stringify());
        let text = match method {
            "payments.append" => answer("payment", &payments.append(arg("entry"), now)?),
            "payments.update" => answer("payment", &payments.update(arg("id"), arg("patch"), now)?),
            "payments.mark_confirmed" => answer(
                "payment",
                &payments.mark_confirmed(arg("id"), arg("receipt"), now)?,
            ),
            "payments.mark_failed" => answer(
                "payment",
                &payments.mark_failed(arg("id"), arg("info"), now)?,
            ),
            "payments.mark_dropped" => answer("payment", &payments.mark_dropped(arg("id"), now)?),
            "payments.set_dropped_seen" => answer(
                "payment",
                &payments.set_dropped_seen(arg("id"), arg("seen_at"), now)?,
            ),
            // The repoll's rows as records (`rowToEntry`): its `tx_hash`,
            // `chain_id` and parsed metadata are `txHash`, `chainId` and
            // `metadata` there, metadata parsed by the same rule.
            "payments.pending" => {
                let records = payments
                    .pending()?
                    .iter()
                    .map(record)
                    .collect::<Result<_, _>>()?;
                answer("payments", &JsValue::Array(records))
            }
            "payments.get_recent" => answer(
                "payments",
                &JsValue::Array(payments.get_recent(arg("filters"))?),
            ),
            "payments.get_by_id" => answer("payment", &payments.get_by_id(arg("id"))?),
            "payments.get_count" => answer("count", &payments.get_count(arg("filters"))?),
            _ => {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "better-sqlite3's changes, a JS number"
                )]
                let removed = payments.clear()? as f64;
                answer("removed", &JsValue::Number(removed))
            }
        };
        RawValue::from_string(text).map_err(|_| crate::vault::internal())
    }

    /// `migrateFromJson`, at the database's first open in this core:
    /// `root`'s `x402-receipts.json` dropped if a `.migrated` is there
    /// already, otherwise read (at most [`MAX_LEGACY_BYTES`]), its rows
    /// imported in one transaction, and the file renamed `.migrated` once
    /// they are committed. A failure leaves the file and is logged, as the
    /// reference logs it; the database serves either way.
    pub fn import(root: &Path, payments: &mut Payments, now_ms: f64) -> Legacy {
        let file = root.join(LEGACY_FILE);
        let migrated = root.join(MIGRATED_FILE);
        if std::fs::symlink_metadata(&file).is_err() {
            return Legacy::Absent;
        }
        if std::fs::symlink_metadata(&migrated).is_ok() {
            let removed = matches!(fsx::remove(&file, || true), Ok(Some(_)));
            if removed {
                crate::log::info(
                    "payments: dropped a stray x402-receipts.json (already migrated)",
                    serde_json::json!({}),
                );
            } else {
                crate::log::error(
                    "payments: cannot remove a stray x402-receipts.json",
                    serde_json::json!({}),
                );
            }
            return Legacy::Stray(removed);
        }
        let kept = |why: &str| {
            crate::log::error(
                "payments: x402-receipts.json not imported",
                serde_json::json!({ "reason": why }),
            );
            Legacy::Kept
        };
        let bytes = match read_file(&file, MAX_LEGACY_BYTES) {
            Read::Bytes(bytes) => bytes,
            Read::Missing => return Legacy::Absent,
            Read::Unreadable => return kept("unreadable"),
        };
        // `readFileSync(path, 'utf-8')`: invalid UTF-8 as U+FFFD, a
        // byte-order mark kept (and refused by `JSON.parse`).
        let text = String::from_utf8_lossy(&bytes);
        let imported = match payments.import_legacy(&text, now_ms) {
            Ok(imported) => imported,
            Err(Error::Thrown(_)) => return kept("refused"),
            Err(_) => return kept("write"),
        };
        crate::log::info(
            "payments: imported x402-receipts.json",
            serde_json::json!({ "imported": imported }),
        );
        let renamed = std::fs::rename(&file, &migrated)
            .and_then(|()| fsx::sync_rename(root, &migrated))
            .is_ok();
        if !renamed {
            crate::log::error(
                "payments: cannot rename x402-receipts.json",
                serde_json::json!({}),
            );
        }
        Legacy::Imported(imported, renamed)
    }
}

fn invalid() -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters")
}

/// `storage`, with the store and what failed: `busy` (another connection
/// holds the database past [`sqlite::BUSY_TIMEOUT`]), `unreadable` (not a
/// regular file the user owns, another schema, not WAL, damaged, or a row
/// no answer holds) or `io` (any other failure, a failed write among them).
/// Nothing was written.
fn storage(kind: &str) -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Storage,
        "The payment history could not be read or written",
    )
    .with_data(serde_json::json!({ "store": "payments", "kind": kind }))
}

fn sqlite_kind(e: &rusqlite::Error) -> &'static str {
    use rusqlite::ErrorCode as Code;
    match e.sqlite_error_code() {
        Some(Code::DatabaseBusy | Code::DatabaseLocked) => "busy",
        Some(Code::DatabaseCorrupt | Code::NotADatabase) => "unreadable",
        _ => "io",
    }
}

fn open_failed(e: sqlite::Error) -> ErrorBody {
    crate::log::error(
        "payments: cannot open payment-history.sqlite",
        serde_json::json!({ "error": e.to_string() }),
    );
    storage(match &e {
        sqlite::Error::Refused | sqlite::Error::JournalMode(_) | sqlite::Error::Version(_) => {
            "unreadable"
        }
        sqlite::Error::Sqlite(e) => sqlite_kind(e),
        sqlite::Error::Io(_) => "io",
    })
}

impl From<Error> for ErrorBody {
    /// The reference's refusal is `invalid_argument` with its message, and
    /// its class in `data.name`, for main to throw again as it was.
    fn from(e: Error) -> Self {
        match e {
            Error::Thrown(thrown) => ErrorBody::new(ErrorCode::InvalidArgument, thrown.message)
                .with_data(serde_json::json!({ "name": thrown.name.as_str() })),
            Error::Blob => storage("unreadable"),
            Error::Sqlite(e) => storage(sqlite_kind(&e)),
        }
    }
}

#[cfg(test)]
mod tests;
