//! The `payments.*` methods (design 0013, "Payment history"; PRF-5g-2's
//! second part), over [`crate::payments`]' glue.
//!
//! [`Store`] answers `not_moved` until `core.hello` names `payments` in
//! `store_moved`, and opens `payment-history.sqlite` only after that, at
//! the first request (0013, "One writer per store"), as the reference's
//! `getDb` opens it at its first use. That first open runs the one-shot
//! import of `x402-receipts.json` ([`Store::import`]).

use std::path::{Path, PathBuf};

use fc_json::JsValue;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_store::file::{Read, read_file};
use fc_store::fsx;
use fc_wallet_state::payments::COLUMNS;
use serde_json::value::RawValue;

use crate::payments::{Error, Payments, SCHEMA};
use crate::sqlite;

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
            // `setDroppedSeenAt` returns nothing: the record written isn't
            // answered.
            "payments.set_dropped_seen" => {
                payments.set_dropped_seen(arg("id"), arg("seen_at"), now)?;
                "{}".to_owned()
            }
            // The repoll's rows as it reads them (`getPending.all()`): each
            // column by its name, as better-sqlite3 reads it, `metadata` as
            // its text.
            "payments.pending" => {
                let rows = payments
                    .pending()?
                    .iter()
                    .map(raw_row)
                    .collect::<Result<_, _>>()?;
                answer("payments", &JsValue::Array(rows))
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
        let imported = match payments.import_legacy(&text, || now_ms) {
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

/// A row as better-sqlite3's `.all()` reads it: an object of its columns,
/// a BLOB cell answering `null`, and logged (0013's `payments-json-values`).
fn raw_row(row: &fc_wallet_state::payments::Row) -> Result<JsValue, Error> {
    let mut blobs = Vec::new();
    let props = COLUMNS
        .iter()
        .zip(row)
        .map(|(column, cell)| {
            let value = cell.to_js().unwrap_or_else(|| {
                blobs.push(*column);
                JsValue::Null
            });
            ((*column).into(), value)
        })
        .collect();
    if !blobs.is_empty() {
        crate::log::warn(
            "a payment row holds a blob: answered as null",
            serde_json::json!({ "columns": blobs }),
        );
    }
    Ok(JsValue::Object(props))
}

fn invalid() -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters")
}

/// `storage`, with the store and what failed: `busy` (another connection
/// holds the database past [`sqlite::BUSY_TIMEOUT`]), `unreadable` (not a
/// regular file the user owns, another schema, not WAL, or damaged) or `io` (any other failure, a failed write among them).
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
            Error::Sqlite(e) => storage(sqlite_kind(&e)),
        }
    }
}

#[cfg(test)]
mod tests;
