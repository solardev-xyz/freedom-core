//! `swarm.history` (design 0015, "Methods main calls"): `publish-history.js`'s
//! reads, removals and writes, over [`crate::stores::history`]'s statements.
//!
//! | op | callers | params | answer |
//! |---|---|---|---|
//! | `list` | chrome, main | | `getEntries()`: every row, the latest first, as `rowToEntry` makes it |
//! | `clear` | chrome, main | | `clearEntries()`: `undefined` |
//! | `remove` | chrome, main | `id` | `removeEntry(id)`: whether it deleted a row |
//! | `add` | main | `entry` | `addEntry(entry)`: the row it inserted, as `rowToEntry` makes it |
//! | `update` | main | `id`, `updates` | `updateEntry(id, updates)`: the row after, or `null` where no row has `id` |
//!
//! The chrome's two IPC handlers wrap `list` and `clear` in `{ success:
//! true, entries }` or `{ success: false, error: err.message }`; that wrap
//! stays main's, around the answer or the thrown error. `remove` has no
//! handler and no caller in the reference; it is main's, and the chrome's.
//!
//! `add` and `update` are main's own (the 2026-11-28 amendment, SWM-6 to
//! SWM-9's plan, core PR K1): the rows `publish-service.js`'s
//! `freedom://publish` handlers keep around an upload, and the agent's
//! publication controller's (`freedom://agent`), which it writes before
//! the upload, while it waits for postage. The chrome calling either is
//! [`Refused::Forbidden`] on the op's name alone, before any member is
//! decoded ([`super::Call::parse`]). Each member is a
//! value in the typed form, read as the reference reads it: an absent
//! `entry` or `updates` is `undefined` (the parameter's default `{}`), an
//! absent `id` binds as NULL. What they throw is the reference's own:
//! `entry.status` or `updates.status` on `null` (V8's `TypeError`, before
//! anything is written), and better-sqlite3's refusal of a value it can't
//! bind.
//! - **`add`**: the insert, then the bound's trim (deviation
//!   `history-bound`), which keeps the row just inserted, as after the
//!   publish machines' inserts, then the row read back by its rowid.
//! - **`update`**: the update; with no row changed the answer is `null`,
//!   otherwise the row read back by `id`.
//!
//! A row with a BLOB cell, which no writer makes, fails the read (deviation
//! `history-blobs`), thrown with the code [`HISTORY_BLOB`]: `list`'s, and
//! `update`'s row read back. A write's or a read's failure throws its text.

use fc_json::{JsString, JsValue};

use super::{Io, Members, Outcome, Refused, invalid};
use crate::stores::Thrown;
use crate::stores::history::{self, RowError, Statement};
use crate::value::Value;

/// The code a read refused for a BLOB cell throws with (deviation
/// `history-blobs`); its message names the column.
pub const HISTORY_BLOB: &str = "history_blob";

/// A `swarm.history` op.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    List,
    Clear,
    Remove {
        id: JsValue,
    },
    /// Main's own: `addEntry(entry)`.
    Add {
        entry: JsValue,
    },
    /// Main's own: `updateEntry(id, updates)`.
    Update {
        id: JsValue,
        updates: JsValue,
    },
}

/// The ops only main makes, forbidden to the chrome on their name alone
/// ([`super::Call::parse`]).
pub(crate) const MAIN_OPS: [&str; 2] = ["add", "update"];

impl Op {
    pub(crate) fn parse(op: String, members: Members) -> Result<Op, Refused> {
        match op.as_str() {
            "list" => {
                members.only("list", &[])?;
                Ok(Op::List)
            }
            "clear" => {
                members.only("clear", &[])?;
                Ok(Op::Clear)
            }
            "remove" => {
                members.only("remove", &["id"])?;
                // `removeEntry(id)` binds whatever it is given; absent is
                // `undefined`, which binds as NULL.
                Ok(Op::Remove {
                    id: members.js("id")?,
                })
            }
            "add" => {
                members.only("add", &["entry"])?;
                Ok(Op::Add {
                    entry: members.js("entry")?,
                })
            }
            "update" => {
                members.only("update", &["id", "updates"])?;
                Ok(Op::Update {
                    id: members.js("id")?,
                    updates: members.js("updates")?,
                })
            }
            other => Err(invalid(format!("swarm.history has no op {other}"))),
        }
    }

    /// The op at `now_ms` (`Date.now()`), its statements run on `io`.
    pub(crate) fn run(&self, now_ms: u64, io: &mut dyn Io) -> Outcome {
        match self {
            Op::List => match io.query(&history::get_entries()) {
                Ok(rows) => match history::entries(&rows) {
                    Ok(entries) => Outcome::Result(Value::from_js(&entries)),
                    Err(error) => Outcome::Thrown(row_thrown(error)),
                },
                Err(text) => Outcome::Thrown(Thrown::error(text.as_str())),
            },
            Op::Clear => match io.run(&history::clear_entries()) {
                Ok(_) => Outcome::Result(Value::Undefined),
                Err(text) => Outcome::Thrown(Thrown::error(text.as_str())),
            },
            Op::Remove { id } => {
                let statement = match history::remove_entry(id) {
                    Ok(statement) => statement,
                    Err(thrown) => return Outcome::Thrown(thrown),
                };
                match io.run(&statement) {
                    Ok(changes) => Outcome::Result(Value::Bool(changes > 0)),
                    Err(text) => Outcome::Thrown(Thrown::error(text.as_str())),
                }
            }
            Op::Add { entry } => match add(entry, now_ms, io) {
                Ok(row) => Outcome::Result(Value::from_js(&row)),
                Err(thrown) => Outcome::Thrown(thrown),
            },
            Op::Update { id, updates } => match update(id, updates, now_ms, io) {
                Ok(row) => Outcome::Result(Value::from_js(&row)),
                Err(thrown) => Outcome::Thrown(thrown),
            },
        }
    }
}

/// `addEntry(entry)`: the insert, the bound after it (which keeps the new
/// row), and the row read back by its rowid
/// (`rowToEntry(getById.get(result.lastInsertRowid))`).
fn add(entry: &JsValue, now_ms: u64, io: &mut dyn Io) -> Result<JsValue, Thrown> {
    history::add_entry_checks(entry)?;
    let insert = history::add_entry(entry, now_ms)?;
    let rowid = io.insert(&insert).map_err(failed)?;
    io.run(&history::trim(Some(rowid))).map_err(failed)?;
    read_back(io, &history::by_rowid(rowid))
}

/// `updateEntry(id, updates)`: the update; `null` where it changed no row,
/// else the row read back by `id` (`rowToEntry(getById.get(id))`).
fn update(
    id: &JsValue,
    updates: &JsValue,
    now_ms: u64,
    io: &mut dyn Io,
) -> Result<JsValue, Thrown> {
    history::update_entry_checks(updates)?;
    let statement = history::update_entry(id, updates, now_ms)?;
    if io.run(&statement).map_err(failed)? == 0 {
        return Ok(JsValue::Null);
    }
    read_back(io, &history::by_id(id)?)
}

/// `rowToEntry(getById.get(…))`: the first row's record, `null` where
/// there is none.
fn read_back(io: &mut dyn Io, statement: &Statement) -> Result<JsValue, Thrown> {
    let rows = io.query(statement).map_err(failed)?;
    match rows.first() {
        Some(row) => history::entry(row).map_err(row_thrown),
        None => Ok(JsValue::Null),
    }
}

/// A statement that failed: its text, thrown.
fn failed(text: JsString) -> Thrown {
    Thrown::error(text.as_str())
}

/// A row that isn't a record: the reference's own throw (a bad
/// timestamp), or the core's refusal of a BLOB cell.
fn row_thrown(error: RowError) -> Thrown {
    match error {
        RowError::Thrown(thrown) => thrown,
        RowError::Blob(column) => Thrown::coded(
            format!("publish-history.sqlite holds a BLOB in column {column}"),
            HISTORY_BLOB,
        ),
        RowError::Short(cells) => Thrown::error(format!(
            "publish-history.sqlite answered a row of {cells} cells"
        )),
    }
}
