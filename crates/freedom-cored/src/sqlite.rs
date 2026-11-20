//! SQLite for the stores whose schema design 0013 keeps, as "Where SQLite
//! lives" puts it: rusqlite with its bundled SQLite, in this binary only.
//! `payment-history.sqlite` is the first (PRF-5g-2): its codec stays pure
//! in `fc-wallet-state`, and this module is the glue.
//!
//! [`open`] opens one database under 0001's rules, as far as SQLite allows:
//! - **The name**, on Unix, has its directory resolved once
//!   (`canonicalize`), never the file's own name: SQLite's
//!   `SQLITE_OPEN_NOFOLLOW` refuses a link anywhere in the name it is given,
//!   so it then refuses only one swapped in later, while a root reached
//!   through a link (macOS's `/var`, a linked home) still opens, as 0001's
//!   roots do.
//! - **The file** is a regular file the user owns, judged on a handle that
//!   didn't follow a symlink, or is created here with mode `0600` (never
//!   through a link), its directory flushed. SQLite then opens that name
//!   without following a link (`SQLITE_OPEN_NOFOLLOW`, Unix only) and
//!   without creating it, and the name must still be the judged file. Its
//!   `-wal` and `-shm` take the database's mode (SQLite's rule). SQLite
//!   opens by path, so 0001's handle-relative directory can't reach into it:
//!   on Windows, a directory swapped above the file between the checks and
//!   SQLite's own opens is outside them.
//! - **WAL**, as the reference sets it (`journal_mode = WAL`), and refused
//!   if SQLite answers another mode.
//! - **`user_version`**, read in a write transaction: 0 is a new database,
//!   given the schema's DDL and version in that one transaction; the
//!   schema's version is opened as it is; any other is refused, with
//!   nothing written.
//!
//! One writer: the caller holds the one connection, and opens a database
//! only once it is named in `store_moved` (design 0013, "Payment history").
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "PRF-5g-2's payments.* are its first callers")
)]

use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use fc_store::fsx;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};

/// A database's schema: the DDL that creates it, and its `user_version`.
pub struct Schema {
    pub version: i32,
    pub ddl: &'static str,
}

#[derive(Debug)]
pub enum Error {
    /// Not a regular file the user owns, a symlink, or no longer the file
    /// judged.
    Refused,
    /// SQLite answered this journal mode to `journal_mode = WAL`.
    JournalMode(String),
    /// A `user_version` neither 0 nor the schema's.
    Version(i32),
    Io(io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Refused => f.write_str("not a regular file the user owns"),
            Error::JournalMode(mode) => write!(f, "journal mode {mode}, not wal"),
            Error::Version(version) => write!(f, "user_version {version}"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Sqlite(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

/// Opens the database at `path` for `schema`, creating it if missing
/// ([module docs](self)).
pub fn open(path: &Path, schema: &Schema) -> Result<Connection, Error> {
    let path = &resolved(path)?;
    let judged = judge(path)?;
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_EXRESCODE,
    )?;
    if !fsx::same_file(&judged, path)? {
        return Err(Error::Refused);
    }
    // The version first: `journal_mode = WAL` is persistent, so a database
    // this core refuses (another schema's) is refused before anything about
    // it changes.
    let version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != 0 && version != schema.version {
        return Err(Error::Version(version));
    }
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(Error::JournalMode(mode));
    }
    // FULL, set on every connection rather than inherited from the build:
    // each commit of a money record is synced (deviation
    // `sqlite-synchronous`; better-sqlite3 reopens a WAL database at NORMAL).
    conn.pragma_update(None, "synchronous", "FULL")?;
    // Rolled back when dropped uncommitted: nothing written but the DDL's
    // one commit. The version is read again inside it, against a writer
    // between the first read and here.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 0 {
        tx.execute_batch(schema.ddl)?;
        tx.pragma_update(None, "user_version", schema.version)?;
        tx.commit()?;
    } else if version != schema.version {
        return Err(Error::Version(version));
    } else {
        drop(tx);
    }
    Ok(conn)
}

/// `path` with its directory resolved (Unix), its own name as given.
#[cfg(unix)]
fn resolved(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or(Error::Refused)?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    Ok(dir.canonicalize()?.join(name))
}

/// Windows' SQLite has no `SQLITE_OPEN_NOFOLLOW`: the name as given.
#[cfg(windows)]
fn resolved(path: &Path) -> Result<PathBuf, Error> {
    Ok(path.to_path_buf())
}

/// The file at `path`, judged on a handle: a regular file the user owns,
/// never through a link, or a new one of mode `0600`.
fn judge(path: &Path) -> Result<File, Error> {
    let file = match fsx::open_regular(path, false)? {
        fsx::Regular::File(file) => file,
        fsx::Regular::Missing => return create(path),
        fsx::Regular::Other => return Err(Error::Refused),
    };
    if owned(&file)? {
        Ok(file)
    } else {
        Err(Error::Refused)
    }
}

/// A new, empty database file (SQLite's for a new database): `create_new`
/// never follows a link and refuses any file already there.
fn create(path: &Path) -> Result<File, Error> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    if let Some(dir) = path.parent() {
        fsx::sync_dir(dir)?;
    }
    Ok(file)
}

#[cfg(unix)]
fn owned(file: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.uid() == rustix::process::getuid().as_raw())
}

/// The owner read from the handle, as `fc_store::file::read_file` reads it
/// (freedom-core#360).
#[cfg(windows)]
fn owned(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsHandle;
    fc_sys::windows::owned_by_current_user(file.as_handle())
}

#[cfg(test)]
mod tests;
