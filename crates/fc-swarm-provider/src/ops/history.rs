//! `swarm.history` (design 0015, "Methods main calls"): `publish-history.js`'s
//! reads and removals, over [`crate::stores::history`]'s statements.
//!
//! | op | params | answer |
//! |---|---|---|
//! | `list` | | `getEntries()`: every row, the latest first, as `rowToEntry` makes it |
//! | `clear` | | `clearEntries()`: `undefined` |
//! | `remove` | `id` | `removeEntry(id)`: whether it deleted a row |
//!
//! The chrome's two IPC handlers wrap `list` and `clear` in `{ success:
//! true, entries }` or `{ success: false, error: err.message }`; that wrap
//! stays main's, around the answer or the thrown error. `remove` has no
//! handler and no caller in the reference; it is main's, and the chrome's.
//! A row with a BLOB cell, which no writer makes, fails the read (deviation
//! `history-blobs`), thrown with the code [`HISTORY_BLOB`].

use fc_json::JsValue;

use super::{Io, Members, Outcome, Refused, invalid};
use crate::stores::Thrown;
use crate::stores::history::{self, RowError};
use crate::value::Value;

/// The code a read refused for a BLOB cell throws with (deviation
/// `history-blobs`); its message names the column.
pub const HISTORY_BLOB: &str = "history_blob";

/// A `swarm.history` op.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    List,
    Clear,
    Remove { id: JsValue },
}

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
            other => Err(invalid(format!("swarm.history has no op {other}"))),
        }
    }

    /// The op, its statements run on `io`.
    pub(crate) fn run(&self, io: &mut dyn Io) -> Outcome {
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
        }
    }
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
