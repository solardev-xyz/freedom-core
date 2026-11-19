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
//! The methods that call these, their callers, `store_moved` and the
//! import's files are PRF-5g-2's second part.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "payments.* (PRF-5g-2's second part) are its first callers"
    )
)]

use std::fmt;

use fc_json::JsValue;
use fc_wallet_state::payments::{self as codec, Bind, Cell, Row, Statement, Thrown};
use rusqlite::types::{ToSqlOutput, Value, ValueRef};
use rusqlite::{Connection, ToSql, Transaction, TransactionBehavior};

use crate::sqlite::Schema;

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

#[cfg(test)]
mod tests;
