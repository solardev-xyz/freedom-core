//! The core's files on disk (design 0013, "How the core writes them"): what
//! every file the core writes shares, under design 0001's rules ("Writes and
//! durability").
//!
//! - [`fsx`]: the durable single-file write (temp file, fsync, check,
//!   commit gate, rename, directory flush), the durable removal, and the
//!   bounded read of a regular file judged on its open handle.
//! - [`anchor`]: a directory opened once and reached through no symlink
//!   below it, each operation relative to its handle on Unix.
//! - [`file`]: one store file (0012's permission files, the phone payments,
//!   and 0013's stores as they move): read under 0001's rules, written with
//!   a test build's failure hooks, and renamed aside when it can't be read.
//! - [`journal`]: the JSON Lines journal, in freedom-browser's
//!   `durable-journal.js` format and rules (the intent journal's).
//!
//! A service crate: it does file I/O, and nothing else. It reads no
//! environment variable and writes no log. A test build's hooks come in as
//! a [`Hooks`] value at each write; a failed flush after a commit is
//! reported to the function the process installs
//! ([`fsx::report_flush_failures`]).

pub mod anchor;
pub mod file;
pub mod fsx;
pub mod journal;

use std::path::Path;

/// A step of a durable write that a test build can make fail
/// ([`Hooks::fails`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Writing the temp file.
    Write,
    /// Its fsync.
    Fsync,
    /// The rename over the target (before it: the target is untouched).
    Rename,
    /// The directory's flush after the rename (the change is in place, and
    /// reported as not durable).
    Flush,
    /// Cutting a failed append back off a journal ([`journal`]): the end of
    /// the file is then unknown.
    Truncate,
}

impl Step {
    /// The step's name in a test hook's spec: `write`, `fsync`, `rename`,
    /// `flush`, `truncate`.
    pub fn name(self) -> &'static str {
        match self {
            Step::Write => "write",
            Step::Fsync => "fsync",
            Step::Rename => "rename",
            Step::Flush => "flush",
            Step::Truncate => "truncate",
        }
    }
}

/// What a test build injects into a durable write ([`fsx::replace`],
/// [`file::write_file`]). Every method's default does nothing, as in every
/// build without test hooks ([`NoHooks`]).
pub trait Hooks {
    /// Whether `step` fails as if the OS had failed it: before the rename,
    /// the target is left as it was and the temp file removed; at the
    /// flush, the change is in place and reported not durable.
    fn fails(&self, step: Step) -> bool {
        let _ = step;
        false
    }

    /// Runs once the staged temp file is written, checked and allowed to
    /// commit, right before its name is compared with the file written: a
    /// test stands a same-user process's swap there.
    fn checked(&self, temp: &Path) {
        let _ = temp;
    }
}

/// No hooks: what every write gets outside a test build.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl Hooks for NoHooks {}
