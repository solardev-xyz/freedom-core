//! `payment-history.sqlite`'s codec (design 0013, "Payment history"): the
//! rows, checks and statements of freedom-browser's
//! `src/main/payment-history.js`, and its one-shot import's mapping of
//! `x402-receipts.json`.
//!
//! The crate does no I/O, so SQLite stays `freedom-cored`'s ("Where SQLite
//! lives"): each operation here is the reference function's work up to the
//! driver, as [`Statement`]s with the reference's SQL text and its
//! parameters bound as better-sqlite3 binds JavaScript values ([`bind`]),
//! and back from the rows SQLite answers ([`Cell`]) to the reference's
//! records ([`record`]). SQLite itself then applies the columns' affinities
//! to those values exactly as under the reference, so a non-integer
//! `chainId` stays a REAL, a whole number in a TEXT column reads `21000.0`,
//! and `metadata` is the text `JSON.stringify` makes ([`fc_json`]).
//!
//! The refusals are the reference's, with its messages ([`Thrown`]): its own
//! checks, V8's for a property read of `null`, and better-sqlite3's binder's
//! for a value it can't bind. `vectors/sqlite.json`'s `payments` is the
//! contract (AGENTS rule 5).

use fc_json::{JsString, JsValue};

use crate::js;

/// The schema's `user_version`.
pub const SCHEMA_VERSION: i32 = 1;

/// The DDL `migrateDatabase` runs, byte for byte: SQLite keeps each
/// statement's text in `sqlite_master`, so a database the core creates
/// reads back the reference's rows (`vectors/sqlite.json`).
pub const DDL: &str = r#"
      CREATE TABLE IF NOT EXISTS payments (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        kind          TEXT    NOT NULL,
        chain_id      INTEGER NOT NULL,
        tx_hash       TEXT,
        from_address  TEXT,
        to_address    TEXT,
        asset         TEXT,
        amount        TEXT    NOT NULL,
        origin        TEXT,
        url           TEXT,
        status        TEXT    NOT NULL,
        created_at    INTEGER NOT NULL,
        confirmed_at  INTEGER,
        gas_used      TEXT,
        gas_price     TEXT,
        metadata      TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_payments_created ON payments(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_payments_kind    ON payments(kind);
      CREATE INDEX IF NOT EXISTS idx_payments_chain   ON payments(chain_id);
      CREATE INDEX IF NOT EXISTS idx_payments_origin  ON payments(origin);
      CREATE INDEX IF NOT EXISTS idx_payments_tx_hash ON payments(tx_hash);
      CREATE INDEX IF NOT EXISTS idx_payments_status  ON payments(status);
    "#;

/// The table's columns in their order, which `SELECT *` answers.
pub const COLUMNS: [&str; 16] = [
    "id",
    "kind",
    "chain_id",
    "tx_hash",
    "from_address",
    "to_address",
    "asset",
    "amount",
    "origin",
    "url",
    "status",
    "created_at",
    "confirmed_at",
    "gas_used",
    "gas_price",
    "metadata",
];

/// The record's keys, in `rowToEntry`'s order, one per column.
const KEYS: [&str; 16] = [
    "id",
    "kind",
    "chainId",
    "txHash",
    "fromAddress",
    "toAddress",
    "asset",
    "amount",
    "origin",
    "url",
    "status",
    "createdAt",
    "confirmedAt",
    "gasUsed",
    "gasPrice",
    "metadata",
];

const METADATA: usize = 15;
const STATUS: usize = 10;

/// `KINDS`.
pub const KINDS: [&str; 5] = [
    "x402",
    "wallet-send",
    "dapp-send",
    "safe-send",
    "safe-deploy",
];

/// `FINAL_STATUSES`.
pub const FINAL_STATUSES: [&str; 9] = [
    "confirmed",
    "failed",
    "settled",
    "no-receipt",
    "taken",
    "dropped",
    "unconfirmed",
    "wrong-transaction",
    "unknown",
];

const PENDING: &str = "pending";
const X402: &str = "x402";

/// `markDropped`'s reason, merged into the row's metadata.
pub const DROPPED_REASON: &str = "nonce used by another transaction";

/// The legacy store, at the profile's `userData` root.
pub const LEGACY_FILE: &str = "x402-receipts.json";
/// The legacy store's name once imported: `x402-receipts.json.migrated`.
pub const MIGRATED_SUFFIX: &str = ".migrated";

/// The statements' text, as the reference prepares them.
pub const INSERT_SQL: &str = "
      INSERT INTO payments (
        kind, chain_id, tx_hash, from_address, to_address, asset, amount,
        origin, url, status, created_at, confirmed_at, gas_used, gas_price, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ";
pub const UPDATE_SQL: &str = "
      UPDATE payments SET
        tx_hash      = COALESCE(?, tx_hash),
        status       = COALESCE(?, status),
        confirmed_at = COALESCE(?, confirmed_at),
        gas_used     = COALESCE(?, gas_used),
        gas_price    = COALESCE(?, gas_price),
        metadata     = COALESCE(?, metadata)
      WHERE id = ?
    ";
pub const BY_ID_SQL: &str = "SELECT * FROM payments WHERE id = ?";
pub const PENDING_SQL: &str = "
      SELECT * FROM payments WHERE status = 'pending' ORDER BY created_at ASC
    ";
pub const CLEAR_SQL: &str = "DELETE FROM payments";
const LEGACY_ROWS_SQL: &str =
    "SELECT * FROM payments WHERE kind = ? ORDER BY created_at DESC LIMIT ? OFFSET ?";

/// `getRecent`'s and `getCount`'s bounds.
const MAX_LIMIT: i32 = 500;
const DEFAULT_LIMIT: f64 = 50.0;

/// A statement parameter as better-sqlite3 binds a JavaScript value: a
/// number as a double (`sqlite3_bind_double`), a string as its UTF-8 (V8's,
/// which writes a lone surrogate as U+FFFD), `null` and `undefined` as
/// NULL.
#[derive(Debug, Clone, PartialEq)]
pub enum Bind {
    Null,
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

impl Cell {
    /// The value better-sqlite3 reads: an INTEGER as the nearest double, as
    /// without `safeIntegers`. `None` for a BLOB, which the reference reads
    /// as a `Buffer` and no JSON holds. No statement here writes one, but the
    /// reference does when a caller hands it a `Buffer` (design 0013's
    /// `payments-json-values`).
    pub fn to_js(&self) -> Option<JsValue> {
        Some(match self {
            Cell::Null => JsValue::Null,
            #[expect(
                clippy::cast_precision_loss,
                reason = "better-sqlite3 reads an INTEGER as the nearest double"
            )]
            Cell::Integer(n) => JsValue::Number(*n as f64),
            Cell::Real(n) => JsValue::Number(*n),
            Cell::Text(text) => JsValue::string(text.as_str()),
            Cell::Blob(_) => return None,
        })
    }

    fn is_text(&self, text: &str) -> bool {
        matches!(self, Cell::Text(t) if t == text)
    }
}

/// The class of a JavaScript error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorName {
    Error,
    TypeError,
    RangeError,
    SyntaxError,
}

impl ErrorName {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorName::Error => "Error",
            ErrorName::TypeError => "TypeError",
            ErrorName::RangeError => "RangeError",
            ErrorName::SyntaxError => "SyntaxError",
        }
    }
}

/// What the reference throws, with its class and message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Thrown {
    pub name: ErrorName,
    pub message: String,
}

impl Thrown {
    fn error(message: impl Into<String>) -> Self {
        Thrown {
            name: ErrorName::Error,
            message: message.into(),
        }
    }

    fn type_error(message: impl Into<String>) -> Self {
        Thrown {
            name: ErrorName::TypeError,
            message: message.into(),
        }
    }

    fn range_error(message: &str) -> Self {
        Thrown {
            name: ErrorName::RangeError,
            message: message.into(),
        }
    }
}

impl From<fc_json::ToPrimitiveError> for Thrown {
    fn from(error: fc_json::ToPrimitiveError) -> Self {
        Thrown::type_error(error.to_string())
    }
}

/// A row as SQLite answers it, one cell per column ([`COLUMNS`]).
pub type Row = Vec<Cell>;

/// A statement and the parameters it runs with.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub sql: String,
    pub params: Vec<Bind>,
}

// Statics, not consts: `JsValue` has a `Drop`, so a const's reference
// isn't promoted to `'static`.
static UNDEFINED: JsValue = JsValue::Undefined;
static NULL: JsValue = JsValue::Null;

/// `value[key]` for the property names the reference reads (none is on
/// `Object.prototype`, `Array.prototype` or `String.prototype`): `undefined`
/// where absent or on a primitive, V8's `TypeError` on `null` or
/// `undefined`.
fn prop<'v>(value: &'v JsValue, key: &str) -> Result<&'v JsValue, Thrown> {
    match value {
        JsValue::Null | JsValue::Undefined => Err(Thrown::type_error(format!(
            "Cannot read properties of {} (reading '{key}')",
            if matches!(value, JsValue::Null) {
                "null"
            } else {
                "undefined"
            }
        ))),
        JsValue::Object(_) => Ok(value.get(key).unwrap_or(&UNDEFINED)),
        _ => Ok(&UNDEFINED),
    }
}

/// `value ?? null`.
fn or_null(value: &JsValue) -> &JsValue {
    if matches!(value, JsValue::Undefined) {
        &NULL
    } else {
        value
    }
}

fn finite(value: &JsValue) -> Option<f64> {
    match value {
        JsValue::Number(n) if n.is_finite() => Some(*n),
        _ => None,
    }
}

/// `isFinalStatus(status)`: a string in [`FINAL_STATUSES`].
fn is_final(status: &JsValue) -> bool {
    status
        .as_js_string()
        .is_some_and(|s| FINAL_STATUSES.iter().any(|f| s == *f))
}

/// `value ? JSON.stringify(value) : null`.
fn stringified(value: &JsValue) -> JsValue {
    if value.truthy() {
        JsValue::string(value.stringify())
    } else {
        JsValue::Null
    }
}

/// Binds the arguments of a `run`, `get` or `all` call on a statement with
/// `count` anonymous parameters, as better-sqlite3's `Binder` does: an
/// array's items bind one parameter each; a plain object (every JSON object)
/// binds named parameters, of which these statements have none, so it binds
/// nothing, and a second one is refused; anything else binds one parameter.
/// A boolean, or an array or object inside an array, can't be bound.
pub fn bind(args: &[&JsValue], count: usize) -> Result<Vec<Bind>, Thrown> {
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

fn statement(sql: &str, args: &[&JsValue], count: usize) -> Result<Statement, Thrown> {
    Ok(Statement {
        sql: sql.to_owned(),
        params: bind(args, count)?,
    })
}

/// `append(entry)` up to its insert: the kind, `chainId` and `amount`
/// checked; `createdAt` and the status defaulted; `confirmed_at` stamped
/// for a final status; `metadata` stringified. `entry` is `undefined` when
/// absent (the default `{}`). The caller reads the inserted row back by its
/// rowid.
pub fn append(entry: &JsValue, now_ms: f64) -> Result<Statement, Thrown> {
    let empty = JsValue::Object(Vec::new());
    let entry = if matches!(entry, JsValue::Undefined) {
        &empty
    } else {
        entry
    };
    let kind = prop(entry, "kind")?;
    if !kind
        .as_js_string()
        .is_some_and(|k| KINDS.iter().any(|known| k == *known))
    {
        return Err(Thrown::error(format!(
            "payment-history: unknown kind '{}'",
            kind.js_string()?
        )));
    }
    let chain_id = prop(entry, "chainId")?;
    if finite(chain_id).is_none() {
        return Err(Thrown::error(
            "payment-history: chainId must be a finite number",
        ));
    }
    let amount = prop(entry, "amount")?;
    let digits = amount
        .as_js_string()
        .is_some_and(|a| !a.is_empty() && a.units().all(|u| (0x30..=0x39).contains(&u)));
    if !digits {
        return Err(Thrown::error(
            "payment-history: amount must be a digit string",
        ));
    }
    let created_at = JsValue::Number(finite(prop(entry, "createdAt")?).unwrap_or(now_ms));
    let status = prop(entry, "status")?;
    let status = if status.truthy() {
        status.clone()
    } else if kind.as_str() == Some(X402) {
        JsValue::string("settled")
    } else {
        JsValue::string(PENDING)
    };
    let confirmed_at = if is_final(&status) {
        created_at.clone()
    } else {
        JsValue::Null
    };
    let metadata = stringified(prop(entry, "metadata")?);
    insert(
        entry,
        &[kind, chain_id],
        &status,
        &created_at,
        &confirmed_at,
        &metadata,
    )
}

/// `insertRow(row)`: `row` holds the entry's other fields.
fn insert(
    row: &JsValue,
    kind_chain: &[&JsValue; 2],
    status: &JsValue,
    created_at: &JsValue,
    confirmed_at: &JsValue,
    metadata: &JsValue,
) -> Result<Statement, Thrown> {
    let field = |key| prop(row, key).map(or_null);
    let args = [
        kind_chain[0],
        kind_chain[1],
        field("txHash")?,
        field("fromAddress")?,
        field("toAddress")?,
        field("asset")?,
        prop(row, "amount")?,
        field("origin")?,
        field("url")?,
        status,
        created_at,
        or_null(confirmed_at),
        field("gasUsed")?,
        field("gasPrice")?,
        or_null(metadata),
    ];
    statement(INSERT_SQL, &args, 15)
}

/// `update(id, patch)`'s statement. `patch` is `undefined` when absent (the
/// default `{}`); `id` binds as given. The caller answers `null` when it
/// changed no row, and otherwise the row read back by `id` ([`by_id`]).
pub fn update(id: &JsValue, patch: &JsValue, now_ms: f64) -> Result<Statement, Thrown> {
    let empty = JsValue::Object(Vec::new());
    let patch = if matches!(patch, JsValue::Undefined) {
        &empty
    } else {
        patch
    };
    let status = prop(patch, "status")?;
    let to_final = status.truthy() && is_final(status);
    let given = prop(patch, "confirmedAt")?;
    let confirmed_at = match given {
        JsValue::Undefined | JsValue::Null if to_final => JsValue::Number(now_ms),
        JsValue::Undefined | JsValue::Null => JsValue::Null,
        other => other.clone(),
    };
    let tx_hash = or_null(prop(patch, "txHash")?);
    let gas_used = or_null(prop(patch, "gasUsed")?);
    let gas_price = or_null(prop(patch, "gasPrice")?);
    let metadata = stringified(prop(patch, "metadata")?);
    let args = [
        tx_hash,
        or_null(status),
        &confirmed_at,
        gas_used,
        gas_price,
        &metadata,
        or_null(id),
    ];
    statement(UPDATE_SQL, &args, 7)
}

fn object(props: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(
        props
            .into_iter()
            .map(|(k, v)| (JsString::from(k), v))
            .collect(),
    )
}

/// `markConfirmed(id, receipt)`'s patch, for [`update`]. `receipt` is
/// `undefined` when absent.
pub fn confirmed_patch(receipt: &JsValue) -> Result<JsValue, Thrown> {
    let empty = JsValue::Object(Vec::new());
    let receipt = if matches!(receipt, JsValue::Undefined) {
        &empty
    } else {
        receipt
    };
    let gas_used = prop(receipt, "gasUsed")?.clone();
    let gas_price = match prop(receipt, "gasPrice")? {
        JsValue::Undefined | JsValue::Null => prop(receipt, "effectiveGasPrice")?.clone(),
        given => given.clone(),
    };
    let confirmed_at = prop(receipt, "confirmedAt")?.clone();
    Ok(object(vec![
        ("status", JsValue::string("confirmed")),
        ("gasUsed", gas_used),
        ("gasPrice", gas_price),
        ("confirmedAt", confirmed_at),
    ]))
}

/// `markFailed(id, { reason, gasUsed, gasPrice })`'s patch, for [`update`]:
/// a reason replaces the row's metadata. `info` is `undefined` when absent.
pub fn failed_patch(info: &JsValue) -> Result<JsValue, Thrown> {
    let destructure = |key: &str| match info {
        JsValue::Null => Err(Thrown::type_error(format!(
            "Cannot destructure property '{key}' of '(intermediate value)(intermediate value)(intermediate value)' as it is null."
        ))),
        JsValue::Undefined => Ok(JsValue::Undefined),
        other => prop(other, key).cloned(),
    };
    let reason = destructure("reason")?;
    let gas_used = destructure("gasUsed")?;
    let gas_price = destructure("gasPrice")?;
    let metadata = if reason.truthy() {
        object(vec![("failureReason", reason)])
    } else {
        JsValue::Undefined
    };
    Ok(object(vec![
        ("status", JsValue::string("failed")),
        ("gasUsed", gas_used),
        ("gasPrice", gas_price),
        ("metadata", metadata),
    ]))
}

/// `{ ...value }`: an object's own properties, an array's items or a
/// string's UTF-16 code units under their indices, and nothing for any
/// other value.
fn spread(value: &JsValue) -> JsValue {
    let mut out = JsValue::Object(Vec::new());
    match value {
        JsValue::Object(props) => {
            for (key, item) in props {
                out.set(key.clone(), item.clone());
            }
        }
        JsValue::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                out.set(index.to_string(), item.clone());
            }
        }
        JsValue::String(text) => {
            for (index, unit) in text.units().enumerate() {
                out.set(
                    index.to_string(),
                    JsValue::String(JsString::from_units(&[unit])),
                );
            }
        }
        _ => {}
    }
    out
}

/// `markDropped(id)`'s patch, for [`update`], from the row read by `id` in
/// the same transaction: `None` (the answer `null`, nothing written) unless
/// the row exists and is still pending. Its metadata is kept, with the
/// reason merged in.
pub fn dropped_patch(existing: Option<&Row>) -> Option<JsValue> {
    let row = existing?;
    if !row
        .get(STATUS)
        .is_some_and(|status| status.is_text(PENDING))
    {
        return None;
    }
    let metadata = row_metadata(row);
    let mut merged = spread(if metadata.truthy() { &metadata } else { &NULL });
    merged.set("failureReason", JsValue::string(DROPPED_REASON));
    Some(object(vec![
        ("status", JsValue::string("dropped")),
        ("metadata", merged),
    ]))
}

/// `setDroppedSeenAt(row, seenAt)`'s patch, the repoll's write, for
/// [`update`], from the row read by `id` in the same transaction: `None`
/// (nothing written) unless the row exists and is still pending. A
/// `seen_at` of `null` deletes `txDroppedSeenAt` from the metadata, and any
/// other value sets it (`undefined`, which JSON never holds, would leave the
/// key out of the text).
pub fn dropped_seen_patch(current: Option<&Row>, seen_at: &JsValue) -> Option<JsValue> {
    let row = current?;
    if !row
        .get(STATUS)
        .is_some_and(|status| status.is_text(PENDING))
    {
        return None;
    }
    let metadata = row_metadata(row);
    let mut merged = spread(if metadata.truthy() { &metadata } else { &NULL });
    if matches!(seen_at, JsValue::Null) {
        if let JsValue::Object(props) = &mut merged {
            props.retain(|(key, _)| key != "txDroppedSeenAt");
        }
    } else {
        merged.set("txDroppedSeenAt", seen_at.clone());
    }
    Some(object(vec![("metadata", merged)]))
}

/// `rowMetadata(row)`, and `rowToEntry`'s metadata: `JSON.parse` of a
/// truthy cell, `null` where it throws.
fn row_metadata(row: &Row) -> JsValue {
    let Some(cell) = row.get(METADATA) else {
        return JsValue::Null;
    };
    let text = match cell {
        Cell::Text(text) if !text.is_empty() => text.clone(),
        Cell::Integer(_) | Cell::Real(_) => match cell.to_js() {
            Some(n) if n.truthy() => n.js_string().unwrap_or_default(),
            _ => return JsValue::Null,
        },
        _ => return JsValue::Null,
    };
    fc_json::parse(&text).unwrap_or(JsValue::Null)
}

/// `getById(id)`'s statement.
pub fn by_id(id: &JsValue) -> Result<Statement, Thrown> {
    statement(BY_ID_SQL, &[or_null(id)], 1)
}

/// `rowToEntry(row)`: the record, camelCase, with `metadata` parsed. A
/// BLOB cell, which the reference answers as a `Buffer`, answers `null`
/// (design 0013's `payments-json-values`), and the row is still a record.
pub fn record(row: &Row) -> JsValue {
    let mut props = Vec::with_capacity(KEYS.len());
    for (index, key) in KEYS.iter().enumerate() {
        let value = if index == METADATA {
            row_metadata(row)
        } else {
            row.get(index)
                .and_then(Cell::to_js)
                .unwrap_or(JsValue::Null)
        };
        props.push((JsString::from(*key), value));
    }
    JsValue::Object(props)
}

/// The repoll's read: every pending row, oldest first. The caller reads
/// them as `SELECT *` answers.
pub fn pending() -> Statement {
    Statement {
        sql: PENDING_SQL.to_owned(),
        params: Vec::new(),
    }
}

/// `clear()`'s statement; the answer is the rows it deleted.
pub fn clear() -> Statement {
    Statement {
        sql: CLEAR_SQL.to_owned(),
        params: Vec::new(),
    }
}

/// `sanitizeFilters(raw)` and `buildWhere`: the filter keys' values as
/// given, `limit` and `offset` clamped.
struct Filters<'v> {
    kind: &'v JsValue,
    chain_id: &'v JsValue,
    origin: &'v JsValue,
    status: &'v JsValue,
    limit: Option<f64>,
    offset: Option<f64>,
}

/// `Number(value) | 0`.
fn int32(value: &JsValue) -> Result<i32, Thrown> {
    let n = js::to_number(value)?;
    if !n.is_finite() {
        return Ok(0);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ToInt32: the value modulo 2^32, below 2^32 here"
    )]
    let low = n.trunc().rem_euclid(4_294_967_296.0) as u32;
    Ok(low.cast_signed())
}

fn filters(raw: &JsValue) -> Result<Filters<'_>, Thrown> {
    let kind = prop(raw, "kind")?;
    let chain_id = prop(raw, "chainId")?;
    let origin = prop(raw, "origin")?;
    let status = prop(raw, "status")?;
    let limit = match prop(raw, "limit")? {
        JsValue::Undefined => None,
        given => Some(f64::from(int32(given)?.clamp(0, MAX_LIMIT))),
    };
    let offset = match prop(raw, "offset")? {
        JsValue::Undefined => None,
        given => Some(f64::from(int32(given)?.max(0))),
    };
    Ok(Filters {
        kind,
        chain_id,
        origin,
        status,
        limit,
        offset,
    })
}

fn where_clause<'v>(filters: &Filters<'v>) -> (String, Vec<&'v JsValue>) {
    let mut terms = Vec::new();
    let mut params = Vec::new();
    if filters.kind.truthy() {
        terms.push("kind = ?");
        params.push(filters.kind);
    }
    if !matches!(filters.chain_id, JsValue::Undefined) {
        terms.push("chain_id = ?");
        params.push(filters.chain_id);
    }
    if filters.origin.truthy() {
        terms.push("origin = ?");
        params.push(filters.origin);
    }
    if filters.status.truthy() {
        terms.push("status = ?");
        params.push(filters.status);
    }
    let clause = if terms.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", terms.join(" AND "))
    };
    (clause, params)
}

/// `getRecent(filters)`'s statement: `filters` is `undefined` when absent
/// (the default `{}`).
pub fn get_recent(filters_given: &JsValue) -> Result<Statement, Thrown> {
    let empty = JsValue::Object(Vec::new());
    let raw = if matches!(filters_given, JsValue::Undefined) {
        &empty
    } else {
        filters_given
    };
    let safe = filters(raw)?;
    let (clause, mut params) = where_clause(&safe);
    let sql = format!("SELECT * FROM payments {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?");
    let limit = JsValue::Number(safe.limit.unwrap_or(DEFAULT_LIMIT));
    let offset = JsValue::Number(safe.offset.unwrap_or(0.0));
    params.push(&limit);
    params.push(&offset);
    // One `?` per argument: the binder spreads an array argument over them.
    let count = params.len();
    statement(&sql, &params, count)
}

/// `getCount(filters)`'s statement, whose one row's one column is the
/// answer.
pub fn get_count(filters_given: &JsValue) -> Result<Statement, Thrown> {
    let empty = JsValue::Object(Vec::new());
    let raw = if matches!(filters_given, JsValue::Undefined) {
        &empty
    } else {
        filters_given
    };
    let safe = filters(raw)?;
    let (clause, params) = where_clause(&safe);
    let sql = format!("SELECT COUNT(*) AS n FROM payments {clause}");
    let count = params.len();
    statement(&sql, &params, count)
}

/// `JSON.parse(text)`'s entries for the import: an array's items, or none.
/// A text that doesn't parse throws, and the file stays for the next open.
pub fn legacy_entries(text: &str) -> Result<Vec<JsValue>, Thrown> {
    match fc_json::parse(text) {
        Ok(mut parsed) => Ok(match &mut parsed {
            JsValue::Array(items) => std::mem::take(items),
            _ => Vec::new(),
        }),
        Err(error) => Err(Thrown {
            name: ErrorName::SyntaxError,
            message: error.to_string(),
        }),
    }
}

/// The rows the import compares an entry with: every x402 row, newest
/// first (`legacyAlreadyImported`'s query).
pub fn legacy_rows() -> Statement {
    Statement {
        sql: LEGACY_ROWS_SQL.to_owned(),
        params: vec![
            Bind::Text(X402.to_owned()),
            Bind::Real(100_000.0),
            Bind::Real(0.0),
        ],
    }
}

/// One legacy entry as the import maps it (`legacyRowFor` and
/// `legacyMetadataFor`).
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyRow {
    /// `JSON.stringify({ legacyId })`.
    pub metadata: String,
    chain_id: f64,
    tx_hash: Option<JsString>,
    asset: Option<JsString>,
    amount: JsString,
    origin: Option<JsString>,
    url: Option<JsString>,
    status: JsString,
    created_at: f64,
    confirmed_at: Option<f64>,
    has_settled_at: bool,
}

fn string_or(value: &JsValue) -> Option<JsString> {
    value.as_js_string().cloned()
}

/// An element of `Array.prototype.join`: `''` for `null` and `undefined`,
/// a string's own code units, and `String(value)` otherwise.
fn join_units(value: &JsValue, out: &mut Vec<u16>) -> Result<(), Thrown> {
    match value {
        JsValue::Null | JsValue::Undefined => {}
        JsValue::String(text) => out.extend(text.units()),
        other => out.extend(other.js_string()?.encode_utf16()),
    }
    Ok(())
}

/// `insertOne(e)`'s mapping of one entry. `now_ms` is the caller's clock,
/// read once, as the reference's `Date.now()`, only for an entry without a
/// finite `settledAt` (seconds; the row holds milliseconds), and before
/// anything else of the entry is read.
pub fn legacy_row(entry: &JsValue, now_ms: impl FnOnce() -> f64) -> Result<LegacyRow, Thrown> {
    let settled_at = finite(prop(entry, "settledAt")?);
    let settled_ms = settled_at.map_or_else(now_ms, |s| s * 1000.0);
    let status = prop(entry, "status")?
        .as_js_string()
        .cloned()
        .unwrap_or_else(|| JsString::from("no-receipt"));
    let id = prop(entry, "id")?;
    let legacy_id = match id.as_js_string() {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            let mut units: Vec<u16> = "legacy".encode_utf16().collect();
            let settled = settled_at.map_or(JsValue::string(""), JsValue::Number);
            let parts = [
                &settled,
                &JsValue::String(status.clone()),
                prop(entry, "chainId")?,
                prop(entry, "txHash")?,
                prop(entry, "url")?,
                prop(entry, "amount")?,
            ];
            for part in parts {
                units.push(u16::from(b':'));
                join_units(part, &mut units)?;
            }
            JsString::from_units(&units)
        }
    };
    let metadata = object(vec![("legacyId", JsValue::String(legacy_id))]).stringify();
    let confirmed_at = is_final(&JsValue::String(status.clone())).then_some(settled_ms);
    Ok(LegacyRow {
        metadata,
        chain_id: finite(prop(entry, "chainId")?).unwrap_or(0.0),
        tx_hash: string_or(prop(entry, "txHash")?),
        asset: string_or(prop(entry, "asset")?),
        amount: string_or(prop(entry, "amount")?).unwrap_or_else(|| JsString::from("0")),
        origin: string_or(prop(entry, "origin")?),
        url: string_or(prop(entry, "url")?),
        status,
        created_at: settled_ms,
        confirmed_at,
        has_settled_at: settled_at.is_some(),
    })
}

/// `cell === value` for a string `value`, by UTF-16 code unit, so a lone
/// surrogate the entry held never equals the U+FFFD SQLite stored.
fn text_is(cell: Option<&Cell>, value: &JsString) -> bool {
    matches!(cell, Some(Cell::Text(text)) if *value == *text.as_str())
}

/// `(cell ?? null) === value`.
fn nullable_is(cell: Option<&Cell>, value: Option<&JsString>) -> bool {
    match value {
        None => matches!(cell, Some(Cell::Null)),
        Some(value) => text_is(cell, value),
    }
}

fn number_is(cell: Option<&Cell>, value: f64) -> bool {
    matches!(cell.and_then(Cell::to_js), Some(JsValue::Number(n)) if n == value)
}

impl LegacyRow {
    /// `row.metadata === metadata || legacyRowMatches(row, legacy)`.
    pub fn imported_as(&self, row: &Row) -> bool {
        if row
            .get(METADATA)
            .is_some_and(|cell| cell.is_text(&self.metadata))
        {
            return true;
        }
        number_is(row.get(2), self.chain_id)
            && nullable_is(row.get(3), self.tx_hash.as_ref())
            && nullable_is(row.get(6), self.asset.as_ref())
            && text_is(row.get(7), &self.amount)
            && nullable_is(row.get(8), self.origin.as_ref())
            && nullable_is(row.get(9), self.url.as_ref())
            && text_is(row.get(STATUS), &self.status)
            && (!self.has_settled_at || number_is(row.get(11), self.created_at))
    }

    /// `insertRow({ ...row, kind: 'x402', metadata })`.
    pub fn insert(&self) -> Statement {
        let text = |value: &JsString| Bind::Text(value.as_str().to_owned());
        let nullable = |value: &Option<JsString>| value.as_ref().map_or(Bind::Null, text);
        Statement {
            sql: INSERT_SQL.to_owned(),
            params: vec![
                Bind::Text(X402.to_owned()),
                Bind::Real(self.chain_id),
                nullable(&self.tx_hash),
                Bind::Null,
                Bind::Null,
                nullable(&self.asset),
                text(&self.amount),
                nullable(&self.origin),
                nullable(&self.url),
                text(&self.status),
                Bind::Real(self.created_at),
                self.confirmed_at.map_or(Bind::Null, Bind::Real),
                Bind::Null,
                Bind::Null,
                Bind::Text(self.metadata.clone()),
            ],
        }
    }
}
