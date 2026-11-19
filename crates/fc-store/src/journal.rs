//! The JSON Lines journal (design 0013, "How the core writes them"): an
//! append-only file whose appends are on disk by the time they are
//! acknowledged, in freedom-browser's `lib/durable-journal.js` format and
//! rules exactly, so each side reads every file the other writes.
//!
//! - **Lines.** One JSON object per line,
//!   `{"v":1,"sha256":"<hex>","record":<record>}`. The checksum covers the
//!   record's exact bytes, `JSON.stringify`'s text in UTF-8 ([`encode_line`]).
//! - **Appends** ([`Journal::append`]) open the file, append, fsync, and only
//!   then return. The file is created with mode `0600`, and the append that
//!   creates it also syncs the directory.
//! - **A failed append** is cut back off the file. If that fails too, the end
//!   of the file is unknown, and the journal refuses every later write
//!   ([`Error::Broken`]) until it is opened again.
//! - **Reading** ([`parse`], [`read`]) accepts a last line without its
//!   newline when it is a whole record whose checksum holds. Any other tail
//!   is torn, an append that never completed: it is ignored. A damaged
//!   complete line is skipped and reported. [`Journal::open`] ends a whole
//!   last record with its newline and cuts a torn tail off.
//! - **Compaction** ([`Journal::compact`]) replaces the file with the records
//!   given: a temp file `<name>.compact-<pid>-<n>.tmp`, fsync, rename, the
//!   directory's sync (on Windows, the renamed file's). A crash before the
//!   rename keeps the old journal; the next open removes every
//!   `<name>.compact-*.tmp`, the reference's leftovers and the core's alike,
//!   as the reference's open removes the core's.
//! - **The bound** is a parameter ([`DEFAULT_MAX_BYTES`], 64 MiB): a larger
//!   file is [`Error::TooLarge`].
//!
//! **Where the core differs from the reference:** a file is read under
//! 0001's rules, judged on its open handle, so another account's file is
//! [`Error::NotAFile`] as a symlink is; a record nested deeper than
//! [`fc_json::MAX_DEPTH`] is a damaged line (design 0003's `json-depth`);
//! and a directory named like a temp file is left, where the reference's
//! open fails on it.
//!
//! One process writes a journal at a time; the caller ensures it.
//! A test build's [`Hooks`] fail each write step: an append's `write` (half
//! the line written), `fsync`, `truncate` (its cut back) and `flush` (the
//! directory's sync when it created the file); a compaction's `write`,
//! `fsync`, `rename` and `flush`.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fc_json::JsValue;
use sha2::{Digest, Sha256};

use crate::fsx;
use crate::{Hooks, Step};

/// The bound a journal is read with unless its caller gives another.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// A journal's mode on Unix.
pub const FILE_MODE: u32 = 0o600;

const LINE_PREFIX: &[u8] = b"{\"v\":1,\"sha256\":\"";
const RECORD_KEY: &[u8] = b"\",\"record\":";
const DIGEST_LENGTH: usize = 64;
const HEADER_LENGTH: usize = LINE_PREFIX.len() + DIGEST_LENGTH + RECORD_KEY.len();

/// Why a journal operation failed, each as the reference's error code says
/// ([`Error::code`]).
#[derive(Debug)]
pub enum Error {
    /// A record that isn't a JSON object (`JOURNAL_INVALID_RECORD`).
    InvalidRecord,
    /// Not a regular file the user owns (`JOURNAL_NOT_A_FILE`).
    NotAFile,
    /// Larger than the bound (`JOURNAL_TOO_LARGE`).
    TooLarge,
    /// A write before [`Journal::open`] (`JOURNAL_NOT_OPEN`).
    NotOpen,
    /// An earlier write couldn't finish, and the file's end is unknown
    /// (`JOURNAL_BROKEN`): open it again. The kind of that write's error.
    Broken(io::ErrorKind),
    /// The OS's error.
    Io(io::Error),
}

impl Error {
    /// The reference's `error.code`; an OS error's kind otherwise.
    pub fn code(&self) -> String {
        match self {
            Error::InvalidRecord => "JOURNAL_INVALID_RECORD".into(),
            Error::NotAFile => "JOURNAL_NOT_A_FILE".into(),
            Error::TooLarge => "JOURNAL_TOO_LARGE".into(),
            Error::NotOpen => "JOURNAL_NOT_OPEN".into(),
            Error::Broken(_) => "JOURNAL_BROKEN".into(),
            Error::Io(e) => format!("{:?}", e.kind()),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidRecord => f.write_str("a journal record must be a JSON object"),
            Error::NotAFile => f.write_str("the journal is not a regular file the user owns"),
            Error::TooLarge => f.write_str("the journal is larger than its bound"),
            Error::NotOpen => f.write_str("the journal is not open"),
            Error::Broken(kind) => write!(
                f,
                "the journal could not finish a write ({kind}); reopen it before writing again"
            ),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Why a complete line was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Not a line of this format, or its record isn't a JSON object.
    Malformed,
    /// The record's bytes don't have the line's checksum.
    Checksum,
}

impl Reason {
    /// The reference's name: `malformed`, `checksum`.
    pub fn name(self) -> &'static str {
        match self {
            Reason::Malformed => "malformed",
            Reason::Checksum => "checksum",
        }
    }
}

/// A damaged complete line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corrupt {
    /// Its number, from 1.
    pub line: u64,
    /// Where it starts.
    pub offset: u64,
    pub reason: Reason,
}

/// What a journal's bytes hold ([`parse`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub records: Vec<JsValue>,
    pub corrupt: Vec<Corrupt>,
    /// Where the last complete record ends.
    pub complete_length: u64,
    /// How many bytes follow it: a torn append.
    pub torn_tail: u64,
    /// The last record is whole but lacks its newline.
    pub unterminated: bool,
}

/// What [`read`] found.
#[derive(Debug, Clone, PartialEq)]
pub struct Read {
    pub missing: bool,
    /// The file's length.
    pub size: u64,
    pub parsed: Parsed,
}

/// One record as its line, newline included: `JSON.stringify`'s text and
/// its SHA-256.
pub fn encode_line(record: &JsValue) -> Result<Vec<u8>, Error> {
    if !matches!(record, JsValue::Object(_)) {
        return Err(Error::InvalidRecord);
    }
    let body = record.stringify();
    let mut line = Vec::with_capacity(HEADER_LENGTH + body.len() + 2);
    line.extend_from_slice(LINE_PREFIX);
    line.extend_from_slice(hex(&Sha256::digest(body.as_bytes())).as_bytes());
    line.extend_from_slice(RECORD_KEY);
    line.extend_from_slice(body.as_bytes());
    line.extend_from_slice(b"}\n");
    Ok(line)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// One complete line, without its newline.
fn decode_line(line: &[u8]) -> Result<JsValue, Reason> {
    if line.len() <= HEADER_LENGTH || line.last() != Some(&b'}') {
        return Err(Reason::Malformed);
    }
    let (header, rest) = line.split_at(HEADER_LENGTH);
    let digest = &header[LINE_PREFIX.len()..LINE_PREFIX.len() + DIGEST_LENGTH];
    if !header.starts_with(LINE_PREFIX)
        || !header.ends_with(RECORD_KEY)
        || !digest
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Reason::Malformed);
    }
    let body = &rest[..rest.len() - 1];
    if hex(&Sha256::digest(body)).as_bytes() != digest {
        return Err(Reason::Checksum);
    }
    // Node's `toString('utf8')`: each ill-formed sequence becomes U+FFFD,
    // by the same maximal-subpart rule.
    match fc_json::parse(&String::from_utf8_lossy(body)) {
        Ok(record @ JsValue::Object(_)) => Ok(record),
        _ => Err(Reason::Malformed),
    }
}

/// A journal's bytes, as the reference's `parseJournal` reads them.
pub fn parse(bytes: &[u8]) -> Parsed {
    let mut records = Vec::new();
    let mut corrupt = Vec::new();
    let mut start = 0;
    let mut line = 0;
    while let Some(at) = bytes[start..].iter().position(|&b| b == b'\n') {
        let end = start + at;
        line += 1;
        match decode_line(&bytes[start..end]) {
            Ok(record) => records.push(record),
            Err(reason) => corrupt.push(Corrupt {
                line,
                offset: start as u64,
                reason,
            }),
        }
        start = end + 1;
    }
    if start < bytes.len() {
        // A whole record whose newline never landed is still a record.
        if let Ok(record) = decode_line(&bytes[start..]) {
            records.push(record);
            return Parsed {
                records,
                corrupt,
                complete_length: bytes.len() as u64,
                torn_tail: 0,
                unterminated: true,
            };
        }
    }
    Parsed {
        records,
        corrupt,
        complete_length: start as u64,
        torn_tail: (bytes.len() - start) as u64,
        unterminated: false,
    }
}

/// Reads a journal without changing it: a regular file the user owns,
/// opened without following a symlink, of at most `max_bytes`.
pub fn read(path: &Path, max_bytes: u64) -> Result<Read, Error> {
    let file = match fsx::open_regular(path, false)? {
        fsx::Regular::File(file) => file,
        fsx::Regular::Other => return Err(Error::NotAFile),
        fsx::Regular::Missing => {
            return Ok(Read {
                missing: true,
                size: 0,
                parsed: parse(&[]),
            });
        }
    };
    if !owned_by_user(&file) {
        return Err(Error::NotAFile);
    }
    if file.metadata()?.len() > max_bytes {
        return Err(Error::TooLarge);
    }
    let bytes = fsx::read_at_most(&file, max_bytes)?.ok_or(Error::TooLarge)?;
    Ok(Read {
        missing: false,
        size: bytes.len() as u64,
        parsed: parse(&bytes),
    })
}

/// 0001's owner rule, as [`crate::file::read_file`] applies it.
fn owned_by_user(file: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        file.metadata()
            .is_ok_and(|m| m.uid() == rustix::process::getuid().as_raw())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        matches!(
            fc_sys::windows::owned_by_current_user(file.as_handle()),
            Ok(true)
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        true
    }
}

/// Syncs `dir`, as the reference's `syncDirectory`: a file system that
/// can't sync a directory (`EINVAL`, `ENOTSUP`, `EISDIR`, `EBADF`) counts
/// as synced. Windows: nothing ([`fsx::sync_dir`]).
fn sync_directory(dir: &Path) -> io::Result<()> {
    match fsx::sync_dir(dir) {
        #[cfg(unix)]
        Err(e)
            if matches!(
                rustix::io::Errno::from_io_error(&e),
                Some(
                    rustix::io::Errno::INVAL
                        | rustix::io::Errno::NOTSUP
                        | rustix::io::Errno::ISDIR
                        | rustix::io::Errno::BADF
                )
            ) =>
        {
            Ok(())
        }
        other => other,
    }
}

fn injected(step: Step) -> io::Error {
    io::Error::other(format!("injected {} failure", step.name()))
}

/// Writes `bytes` to `file` and fsyncs it, with the hooks' `write` (half
/// the bytes written, then the error) and `fsync`.
fn write_synced(file: &mut File, bytes: &[u8], hooks: &dyn Hooks) -> io::Result<()> {
    if hooks.fails(Step::Write) {
        file.write_all(&bytes[..bytes.len() / 2])?;
        return Err(injected(Step::Write));
    }
    file.write_all(bytes)?;
    if hooks.fails(Step::Fsync) {
        return Err(injected(Step::Fsync));
    }
    file.sync_all()
}

/// Cuts `path` back to `len` and fsyncs it, through a handle of its own:
/// on Windows an append-only handle has no `FILE_WRITE_DATA`, so it can't
/// truncate (where the reference's journal ends up broken instead).
fn cut_back(path: &Path, len: u64) -> io::Result<()> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(len)?;
    file.sync_all()
}

/// A journal file, `<dir>/<name>`, written by this process alone.
#[derive(Debug)]
pub struct Journal {
    dir: PathBuf,
    path: PathBuf,
    /// `<name>.compact-`: a compaction's temp files start with it.
    temp_prefix: String,
    max_bytes: u64,
    opened: bool,
    exists: bool,
    /// The file was created, and its directory not synced since.
    entry_unsynced: bool,
    size: u64,
    broken: Option<io::ErrorKind>,
    temps: u32,
}

impl Journal {
    /// The journal `<dir>/<name>`, read with `max_bytes` as its bound. It is
    /// [`Journal::open`]ed (or [`Journal::move_aside`]d) before a write.
    pub fn new(dir: &Path, name: &str, max_bytes: u64) -> Journal {
        Journal {
            dir: dir.to_path_buf(),
            path: dir.join(name),
            temp_prefix: format!("{name}.compact-"),
            max_bytes,
            opened: false,
            exists: false,
            entry_unsynced: false,
            size: 0,
            broken: None,
            temps: 0,
        }
    }

    /// The journal's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes in the journal, as of the last completed operation.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Reads the journal and makes it ready for appends: removes a crashed
    /// compaction's temp files, ends a whole last record with its newline or
    /// cuts a torn tail off, and sets the mode to `0600`. Opening again
    /// (after a failed write) reads the file again.
    ///
    /// An existing file's directory is synced before the journal is ready,
    /// so an entry whose sync failed earlier (a create's, or a compaction's
    /// rename), in this process or one before it, is durable before the
    /// next append is acknowledged.
    pub fn open(&mut self) -> Result<Read, Error> {
        self.open_hooked(&crate::NoHooks)
    }

    /// [`Journal::open`], with `hooks` able to fail the directory sync
    /// ([`Step::Flush`]).
    pub fn open_hooked(&mut self, hooks: &dyn Hooks) -> Result<Read, Error> {
        self.opened = false;
        self.remove_stale_temps()?;
        let result = read(&self.path, self.max_bytes)?;
        let mut length = result.parsed.complete_length;
        if !result.missing {
            if result.parsed.unterminated {
                let mut file = OpenOptions::new().append(true).open(&self.path)?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                length += 1;
            } else if result.parsed.torn_tail > 0 {
                let file = OpenOptions::new().write(true).open(&self.path)?;
                file.set_len(length)?;
                file.sync_all()?;
            }
            fsx::tighten(&self.path)?;
            if hooks.fails(Step::Flush) {
                return Err(Error::Io(injected(Step::Flush)));
            }
            sync_directory(&self.dir)?;
        }
        self.exists = !result.missing;
        self.entry_unsynced = false;
        self.size = length;
        self.broken = None;
        self.opened = true;
        Ok(result)
    }

    fn remove_stale_temps(&self) -> io::Result<()> {
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let stale = entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&self.temp_prefix) && n.ends_with(".tmp"));
            if !stale || entry.file_type()?.is_dir() {
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }

    fn writable(&self) -> Result<(), Error> {
        if !self.opened {
            return Err(Error::NotOpen);
        }
        match self.broken {
            Some(kind) => Err(Error::Broken(kind)),
            None => Ok(()),
        }
    }

    /// Appends one record (a JSON object), returning once its line is
    /// synced to disk.
    pub fn append(&mut self, record: &JsValue, hooks: &dyn Hooks) -> Result<(), Error> {
        let line = encode_line(record)?;
        self.writable()?;
        let mut options = OpenOptions::new();
        options.append(true);
        if self.exists {
            options.create(true);
        } else {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(FILE_MODE);
        }
        let mut file = options.open(&self.path)?;
        if !self.exists {
            self.exists = true;
            self.entry_unsynced = true;
        }
        let written = write_synced(&mut file, &line, hooks);
        drop(file);
        if let Err(error) = written {
            // Take the partial or unsynced line back off, so the file ends
            // where the last acknowledged append left it.
            let cut = if hooks.fails(Step::Truncate) {
                Err(injected(Step::Truncate))
            } else {
                cut_back(&self.path, self.size)
            };
            if cut.is_err() {
                self.broken = Some(error.kind());
            }
            return Err(Error::Io(error));
        }
        self.size += line.len() as u64;
        if self.entry_unsynced {
            let synced = if hooks.fails(Step::Flush) {
                Err(injected(Step::Flush))
            } else {
                sync_directory(&self.dir)
            };
            if let Err(error) = synced {
                // The line is synced, but the file holding it might not
                // survive.
                self.broken = Some(error.kind());
                return Err(Error::Io(error));
            }
            self.entry_unsynced = false;
        }
        Ok(())
    }

    /// Replaces the journal with these records, in this order. Compact only
    /// to records the file already holds (or that fold to the same state),
    /// so that the old file, if a crash keeps it, is still right.
    pub fn compact(&mut self, records: &[JsValue], hooks: &dyn Hooks) -> Result<(), Error> {
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend_from_slice(&encode_line(record)?);
        }
        self.writable()?;
        let (temp, mut file) = self.create_temp()?;
        let staged = write_synced(&mut file, &bytes, hooks).and_then(|()| {
            drop(file);
            if hooks.fails(Step::Rename) {
                return Err(injected(Step::Rename));
            }
            std::fs::rename(&temp, &self.path)
        });
        if let Err(error) = staged {
            let _ = std::fs::remove_file(&temp);
            return Err(Error::Io(error));
        }
        self.exists = true;
        self.entry_unsynced = true;
        self.size = bytes.len() as u64;
        let synced = if hooks.fails(Step::Flush) {
            Err(injected(Step::Flush))
        } else if cfg!(windows) {
            fsx::sync_rename(&self.dir, &self.path)
        } else {
            sync_directory(&self.dir)
        };
        if let Err(error) = synced {
            // Later appends would land in a file whose name may not survive.
            self.broken = Some(error.kind());
            return Err(Error::Io(error));
        }
        self.entry_unsynced = false;
        Ok(())
    }

    /// `<name>.compact-<pid>-<n>.tmp`, created exclusively, mode `0600`.
    fn create_temp(&mut self) -> io::Result<(PathBuf, File)> {
        loop {
            let n = self.temps;
            self.temps = self.temps.wrapping_add(1);
            let temp = self.dir.join(format!(
                "{}{}-{n}.tmp",
                self.temp_prefix,
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(FILE_MODE);
            }
            match options.open(&temp) {
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < u32::MAX => continue,
                opened => return opened.map(|file| (temp, file)),
            }
        }
    }

    /// Moves the journal aside, to `<file>.<tag>` (or `<file>.<tag>-<n>`, the
    /// first free), and starts an empty one, also when `open` refused the
    /// file. The path it was moved to, or `None` when there was no file.
    pub fn move_aside(&mut self, tag: &str) -> Result<Option<PathBuf>, Error> {
        let base = self.path.as_os_str().to_owned();
        let named = |suffix: String| {
            let mut name: OsString = base.clone();
            name.push(suffix);
            PathBuf::from(name)
        };
        let mut target = named(format!(".{tag}"));
        let mut n = 1u64;
        while std::fs::symlink_metadata(&target).is_ok() {
            target = named(format!(".{tag}-{n}"));
            n += 1;
        }
        let moved = match std::fs::rename(&self.path, &target) {
            Ok(()) => Some(target),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::Io(e)),
        };
        if moved.is_some() {
            sync_directory(&self.dir)?;
        }
        self.exists = false;
        self.entry_unsynced = false;
        self.size = 0;
        self.broken = None;
        self.opened = true;
        Ok(moved)
    }
}

#[cfg(test)]
mod tests;
