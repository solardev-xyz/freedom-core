//! The pending Safe transactions, `safe-pending.json` beside the
//! permission files (the hello's `grant_root`, where main's
//! `getFreedomDataPath` puts it), in the reference's text (design 0013,
//! "Pending Safe transactions"; PRF-5f). fc-wallet-state's
//! [`safe_pending`](fc_wallet_state::safe_pending) is the codec.
//!
//! - **Methods:** `safe_pending.get { index } → { entry }` (the entry, or
//!   `null`), `.list {} → { indices }`, `.set { index, entry } → { durable
//!   }` and `.clear { index } → { cleared, durable }` (`cleared`: the
//!   index had an entry), main's alone. `index` is a
//!   wallet index, an integer from 0 to `Number.MAX_SAFE_INTEGER`; `entry`
//!   any JSON value, kept as JS keeps it.
//! - **One writer:** until `core.hello` names `safe_pending` in
//!   `store_moved`, main writes the file. The reads are served from it,
//!   and an unreadable file reads as empty and stays where it is; `set`
//!   and `clear` answer `not_moved` (`data.store`), and nothing is written,
//!   renamed or removed.
//! - **Each request reads the file**, as a fresh load of the reference
//!   would; the core is its only writer once moved.
//! - **An unreadable file** (not a regular file the user owns, over 1 MiB,
//!   or outside the codec's shape) is renamed to
//!   `safe-pending.json.unreadable` once moved, and logged
//!   (`safe-pending-unreadable`): the store reads as empty. If the rename
//!   fails, the reads answer empty and nothing writes the file (`storage`).
//! - **A failed write** (the temp file's write, its fsync, the rename) is
//!   reported, `storage`, with the file as it was
//!   (`safe-pending-write-reported`). A failed directory flush after the
//!   rename leaves the change in place, answered `durable: false`.
//! - **The bound:** a set whose file would be past 1 MiB is refused
//!   (`invalid_argument`), the store unchanged.
//! - **`accounts.remove` of a Safe** clears its entry through
//!   [`SafePending::clear`] once both stores are moved; before
//!   `safe_pending` moves it gets `not_moved` back and leaves the entry to
//!   main (design 0013, "`accounts.remove`").

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use fc_json::JsValue;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_store::file::{Read, read_file, set_aside, write_file};
use fc_store::fsx::{self, Done};
use fc_wallet_state::safe_pending::{
    FILE_NAME, MAX_FILE_BYTES, MAX_INDEX, SafePending as Store, Unreadable,
};
use serde_json::value::RawValue;

use crate::testhooks::GrantWrite;

/// The methods, all main's (fc-protocol's table).
pub const METHODS: [&str; 4] = [
    "safe_pending.get",
    "safe_pending.set",
    "safe_pending.clear",
    "safe_pending.list",
];

/// Its name in `store_moved`, `not_moved`'s `data.store` and the write
/// hooks (`FREEDOM_CORED_TEST_GRANT_WRITE_FAIL`'s `safe_pending:<step>`).
pub const STORE: &str = "safe_pending";

/// Why a write changed nothing on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// `safe_pending` isn't in `store_moved`: main writes the file.
    NotMoved,
    /// The file would be one the core can't read back (past the bound):
    /// the store is unchanged.
    Bound(Unreadable),
    /// The write failed before its rename, or an unreadable file couldn't
    /// be set aside: the file is as it was.
    Storage,
}

impl Failure {
    pub fn error(self) -> ErrorBody {
        match self {
            Failure::NotMoved => ErrorBody::new(
                ErrorCode::NotMoved,
                "main still writes the pending Safe transactions (safe_pending isn't in store_moved)",
            )
            .with_data(serde_json::json!({ "store": STORE })),
            Failure::Bound(why) => ErrorBody::new(
                ErrorCode::InvalidArgument,
                format!("the pending Safe transactions would be unreadable: {why}"),
            ),
            Failure::Storage => ErrorBody::new(
                ErrorCode::Storage,
                "The pending Safe transactions could not be written",
            )
            .with_data(serde_json::json!({ "store": STORE })),
        }
    }
}

/// A clear's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cleared {
    /// The index had an entry (a falsy one included), and the file was
    /// written without it.
    pub had: bool,
    /// `false` when the directory flush after the rename failed: the
    /// change is in place, and may not survive power loss.
    pub durable: bool,
}

/// Where the file is, and who writes it: set at the hello.
struct Place {
    root: PathBuf,
    moved: bool,
}

/// The store as a request finds it.
enum Found {
    Store(Store),
    /// Unreadable, and its set-aside failed: reads answer empty, and
    /// nothing writes the file.
    Stuck,
}

/// `safe-pending.json`. Each operation holds the lock from its read to
/// its write, so a clear from another thread (`accounts.remove`'s) and a
/// request never interleave.
#[derive(Default)]
pub struct SafePending {
    place: Mutex<Option<Place>>,
}

impl SafePending {
    pub fn new() -> Self {
        SafePending::default()
    }

    /// The hello's `grant_root`, and whether `store_moved` names
    /// `safe_pending`. Once moved, a leftover temp file of the core's is
    /// removed.
    pub fn configure(&self, root: PathBuf, moved: bool) {
        if moved && let Err(e) = fsx::remove_temps(&root, FILE_NAME) {
            crate::log::warn(
                "cannot remove the pending Safe transactions' temp files",
                serde_json::json!({ "kind": e.kind().to_string() }),
            );
        }
        *self.lock() = Some(Place { root, moved });
    }

    fn lock(&self) -> MutexGuard<'_, Option<Place>> {
        self.place
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A request: its result's JSON text, or its error.
    pub fn request(&self, method: &str, raw: Option<&str>) -> Result<Box<RawValue>, ErrorBody> {
        let params = fc_json::parse(raw.unwrap_or("{}")).map_err(|_| invalid())?;
        let result = match method {
            "safe_pending.get" => {
                let index = index_param(&params)?;
                let entry = self.read(|store| store.get(index).map(JsValue::stringify));
                format!(r#"{{"entry":{}}}"#, entry.as_deref().unwrap_or("null"))
            }
            "safe_pending.list" => {
                let indices = self.read(|store| store.list());
                serde_json::json!({ "indices": indices }).to_string()
            }
            "safe_pending.set" => {
                self.check_moved()?;
                let index = index_param(&params)?;
                let entry = params.get("entry").cloned().ok_or_else(invalid)?;
                let durable = self.set(index, entry).map_err(Failure::error)?;
                serde_json::json!({ "durable": durable }).to_string()
            }
            "safe_pending.clear" => {
                self.check_moved()?;
                let index = index_param(&params)?;
                let cleared = self.clear(index).map_err(Failure::error)?;
                serde_json::json!({ "cleared": cleared.had, "durable": cleared.durable })
                    .to_string()
            }
            _ => return Err(ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method")),
        };
        RawValue::from_string(result).map_err(|_| crate::vault::internal())
    }

    /// `not_moved` for a write before the name, whatever its parameters.
    pub fn check_moved(&self) -> Result<(), ErrorBody> {
        match &*self.lock() {
            Some(place) if place.moved => Ok(()),
            _ => Err(Failure::NotMoved.error()),
        }
    }

    /// Every entry, in `listPendingIndexes()`'s order, as `getPending`
    /// gives each (a falsy one left out), from the file as it stands: the
    /// Safe methods' `safe.pending` (design 0016, SAFE-2).
    pub fn entries(&self) -> Vec<(u64, JsValue)> {
        self.read(|store| {
            store
                .list()
                .into_iter()
                .filter_map(|index| store.get(index).map(|entry| (index, entry.clone())))
                .collect()
        })
    }

    /// `getPending(index)`, from the file as it stands.
    pub fn entry(&self, index: u64) -> Option<JsValue> {
        self.read(|store| store.get(index).cloned())
    }

    /// A read: the store as the file gives it, empty where there is none
    /// or it is unreadable.
    fn read<T>(&self, answer: impl FnOnce(&Store) -> T) -> T {
        let place = self.lock();
        match place.as_ref().map(found) {
            Some(Found::Store(store)) => answer(&store),
            Some(Found::Stuck) | None => answer(&Store::empty()),
        }
    }

    /// `setPending(index, entry)`: whether the write was durable.
    pub fn set(&self, index: u64, entry: JsValue) -> Result<bool, Failure> {
        self.change(|store| store.set(index, entry).map(|()| true))
            .map(|(_, durable)| durable)
    }

    /// `setPending(index, entry)` only where `vacant` takes the index's
    /// entry as it stands (none, or a falsy one, is `None`), read and
    /// written under one lock, so no other write lands between the check
    /// and the set: `safe.propose`'s (design 0016, SAFE-2's S3). `None`
    /// when `vacant` refused it, with nothing written; otherwise whether
    /// the write was durable.
    pub fn set_where(
        &self,
        index: u64,
        entry: JsValue,
        vacant: impl FnOnce(Option<&JsValue>) -> bool,
    ) -> Result<Option<bool>, Failure> {
        let mut refused = false;
        let (_, durable) = self.change(|store| {
            if !vacant(store.get(index)) {
                refused = true;
                return Ok(false);
            }
            store.set(index, entry).map(|()| true)
        })?;
        Ok((!refused).then_some(durable))
    }

    /// `clearPending(index)` only where `still` takes the index's entry as
    /// it stands (none, or a falsy one, is `None`), read and cleared under
    /// one lock: `safe.executed`'s (design 0016, SAFE-2's S4), which clears
    /// only the SafeTx it names. `None` when `still` refused it, with
    /// nothing written; otherwise the clear's outcome.
    pub fn clear_where(
        &self,
        index: u64,
        still: impl FnOnce(Option<&JsValue>) -> bool,
    ) -> Result<Option<Cleared>, Failure> {
        let mut refused = false;
        let (had, durable) = self.change(|store| {
            if !still(store.get(index)) {
                refused = true;
                return Ok(false);
            }
            Ok(store.clear(index))
        })?;
        Ok((!refused).then_some(Cleared { had, durable }))
    }

    /// `clearPending(index)`: the clear `safe_pending.clear` makes, and
    /// `accounts.remove`'s for a Safe once both stores are moved. Before
    /// `safe_pending` is named, [`Failure::NotMoved`], and nothing is
    /// touched: main clears it.
    pub fn clear(&self, index: u64) -> Result<Cleared, Failure> {
        self.change(|store| Ok(store.clear(index)))
            .map(|(had, durable)| Cleared { had, durable })
    }

    /// Reads the moved store, applies `change` (whether the reference
    /// writes), and writes the file when it does: whether it wrote, and
    /// whether that was durable.
    fn change(
        &self,
        change: impl FnOnce(&mut Store) -> Result<bool, Unreadable>,
    ) -> Result<(bool, bool), Failure> {
        let place = self.lock();
        let Some(place) = place.as_ref().filter(|place| place.moved) else {
            return Err(Failure::NotMoved);
        };
        let Found::Store(mut store) = found(place) else {
            return Err(Failure::Storage);
        };
        if !change(&mut store).map_err(Failure::Bound)? {
            return Ok((false, true));
        }
        let path = place.root.join(FILE_NAME);
        match write_file(&path, store.text().as_bytes(), &GrantWrite(STORE)) {
            Ok(done) => Ok((true, done == Done::Durable)),
            Err(e) => {
                crate::log::error(
                    "the pending Safe transactions' write failed",
                    serde_json::json!({ "kind": e.kind().to_string() }),
                );
                Err(Failure::Storage)
            }
        }
    }
}

/// The file as a request finds it: set aside when unreadable, once moved.
fn found(place: &Place) -> Found {
    let reason = match read_file(&place.root.join(FILE_NAME), MAX_FILE_BYTES) {
        Read::Missing => return Found::Store(Store::empty()),
        Read::Bytes(bytes) => match Store::load(&bytes) {
            Ok(store) => return Found::Store(store),
            Err(why) => why.reason(),
        },
        Read::Unreadable => "file",
    };
    if !place.moved {
        // Main's file: only its writer sets it aside.
        return Found::Store(Store::empty());
    }
    let renamed = set_aside(&place.root, FILE_NAME);
    crate::log::warn(
        "the pending Safe transactions can't be read: renamed aside, the store starts empty",
        serde_json::json!({ "reason": reason, "renamed": renamed.is_ok() }),
    );
    match renamed {
        Ok(_) => Found::Store(Store::empty()),
        Err(_) => Found::Stuck,
    }
}

fn invalid() -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters")
}

/// `index`: a wallet index, an integer from 0 to [`MAX_INDEX`].
fn index_param(params: &JsValue) -> Result<u64, ErrorBody> {
    match params.get("index") {
        Some(JsValue::Number(n)) if n.fract() == 0.0 && (0.0..=MAX_INDEX as f64).contains(n) => {
            Ok(*n as u64)
        }
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clear `accounts.remove` makes: `not_moved` until the name, the
    /// file untouched, then the entry cleared.
    #[test]
    fn a_clear_waits_for_the_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, br#"{"3":{"a":1}}"#).unwrap();
        let store = SafePending::new();
        assert_eq!(store.clear(3), Err(Failure::NotMoved));
        store.configure(dir.path().to_owned(), false);
        assert_eq!(store.clear(3), Err(Failure::NotMoved));
        assert_eq!(store.set(3, JsValue::Null), Err(Failure::NotMoved));
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"3":{"a":1}}"#);
        store.configure(dir.path().to_owned(), true);
        let cleared = |had| Ok(Cleared { had, durable: true });
        assert_eq!(store.clear(3), cleared(true));
        assert_eq!(store.clear(3), cleared(false));
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
    }

    #[test]
    fn index_params() {
        let index = |text: &str| index_param(&fc_json::parse(text).unwrap()).ok();
        assert_eq!(index(r#"{"index":0}"#), Some(0));
        assert_eq!(index(r#"{"index":-0}"#), Some(0));
        assert_eq!(index(r#"{"index":1000000}"#), Some(1_000_000));
        assert_eq!(index(r#"{"index":9007199254740991}"#), Some(MAX_INDEX));
        for bad in [
            r#"{}"#,
            r#"{"index":null}"#,
            r#"{"index":"1"}"#,
            r#"{"index":-1}"#,
            r#"{"index":1.5}"#,
            r#"{"index":9007199254740992}"#,
            r#"{"index":1e400}"#,
            r#"[1]"#,
        ] {
            assert_eq!(index(bad), None, "{bad}");
        }
    }
}
