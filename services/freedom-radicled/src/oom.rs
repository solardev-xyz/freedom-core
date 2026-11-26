//! Out of memory ends the process with exit 71, `out_of_memory`, and is
//! never a request's error (design 0008, "Pools and budgets" and "Errors";
//! design 0010, "The memory cap"). Main restarts the service as after a
//! crash; in the import process, once the import has started, it is
//! `outcome_unknown`, as any crash there is.
//!
//! - **libgit2 and SQLite end it themselves.** `main` calls
//!   `libradicle::process_init` first, which installs libgit2's allocator
//!   and wraps SQLite's: an allocation either can't get ends the process
//!   with 71 at once, on whichever thread it fails, with one line from
//!   libradicle on stderr.
//! - **Rust's allocator** aborts the process, as it does by default.
//! - **The backstop is here,** for an out-of-memory error that reaches the
//!   service although no allocation of theirs failed: zlib's inside libgit2,
//!   which allocates through its own default and whose `Z_MEM_ERROR` in a
//!   stream libgit2 reports as `GIT_ERROR_NOMEMORY`; libgit2's size checks,
//!   which fail so with no allocation tried; and SQLite's refusal of a
//!   request of 2^31 - 256 bytes or more. Wherever a libradicle error
//!   reaches the service's handling, [`check`] runs first, before anything
//!   answers, logs, formats or swallows it, and so does [`check_heartwood`]
//!   for heartwood's own errors, which the service meets without libradicle:
//!   reconciliation's, the online repair's state and the quarantine
//!   record's.
//! - **Neither allocates,** since the heap may be what ran out: each walks
//!   the borrowed error (libradicle's `Error::is_out_of_memory`, and
//!   [`heartwood_counted`] for heartwood's types), and a counted one ends
//!   the process through `fc_service::exit::fail_stop`, one write of the
//!   fixed [`LINE`] to stderr, then `_exit(71)` (`TerminateProcess` on
//!   Windows): no lock, no thread, no teardown, as after libradicle's hooks.
//! - **What it can't count** (0008, "Pools and budgets"): zlib's
//!   `deflateInit` refused for want of memory when libgit2 writes a loose
//!   object, which libgit2 reports as `GIT_ERROR_ZLIB`, as it does a corrupt
//!   object's inflate, so it stays the request's error; and an error that
//!   heartwood or libradicle has already made text, or wrapped in a type of
//!   its own that the walk can't see into (`Error::is_out_of_memory` lists
//!   them).

use std::error::Error as StdError;

use fc_service::Exit;
use radicle::git::raw::{Error as GitError, ErrorClass};
use radicle::storage::git::reconcile::{driver, quarantine, state};

/// The one line the backstop writes as it ends the process: fixed, so that
/// nothing is formatted or allocated, and a log line as main reads them.
pub const LINE: &[u8] =
    b"{\"level\":\"error\",\"msg\":\"out of memory: the process ends\",\"reason\":\"out_of_memory\"}\n";

/// SQLite's `SQLITE_NOMEM`, and the extended `SQLITE_IOERR_NOMEM`
/// (`SQLITE_IOERR | 12 << 8`): its stable result codes, held to the C
/// library's by a test.
const SQLITE_NOMEM: isize = 7;
const SQLITE_IOERR_NOMEM: isize = 3082;

/// Past this many links, a chain is taken to loop: heartwood's and
/// libradicle's are a few deep.
const CHAIN_LIMIT: usize = 64;

/// Ends the process with 71 if `error` is, or wraps, an out-of-memory error
/// of libgit2's or SQLite's (see the module's doc), allocating nothing.
/// Otherwise it returns, and the caller answers or logs `error` as before.
pub fn check(error: &libradicle::Error) {
    if error.is_out_of_memory() {
        fail_stop();
    }
}

/// [`check`], for an error of heartwood's own, borrowed: ends the process
/// with 71 if [`heartwood_counted`] counts it. The caller asks before it
/// takes anything else from `error`.
pub fn check_heartwood<E: StdError + 'static>(error: &E) {
    if heartwood_counted(error) {
        fail_stop();
    }
}

/// Whether `error`, or an error it holds, is libgit2's `GIT_ERROR_NOMEMORY`
/// or SQLite's `SQLITE_NOMEM` (or `SQLITE_IOERR_NOMEM`), walking the
/// borrowed chain without allocating: libradicle's own `Error` by its
/// `is_out_of_memory`; an `io::Error`'s inner error; the heartwood types
/// the service meets, through the variants whose `source()` skips what they
/// hold ([`step`]); and every other error by its `source()`.
pub fn heartwood_counted(error: &(dyn StdError + 'static)) -> bool {
    let mut next = Some(error);
    for _ in 0..CHAIN_LIMIT {
        let Some(error) = next else {
            return false;
        };
        match step(error) {
            Step::Counted => return true,
            Step::Next(after) => next = after,
        }
    }
    false
}

/// What [`heartwood_counted`] finds at one link.
enum Step<'a> {
    /// Out of memory.
    Counted,
    /// The next link to look at, if any.
    Next(Option<&'a (dyn StdError + 'static)>),
}

/// One link: a leaf, or the error it holds.
fn step<'a>(error: &'a (dyn StdError + 'static)) -> Step<'a> {
    if let Some(e) = error.downcast_ref::<libradicle::Error>() {
        return counted_if(e.is_out_of_memory());
    }
    if let Some(e) = error.downcast_ref::<GitError>() {
        return counted_if(e.class() == ErrorClass::NoMemory);
    }
    if let Some(e) = error.downcast_ref::<std::io::Error>() {
        return Step::Next(e.get_ref().map(|e| e as &(dyn StdError + 'static)));
    }
    // heartwood's `transparent` variants, whose `source()` is the wrapped
    // error's own and skips it, and those that hold an error without
    // `#[source]`. Their other variants go on by `source()`.
    if let Some(e) = error.downcast_ref::<state::Error>() {
        return match e {
            state::Error::Sql(e) => sqlite(e.code),
            state::Error::Git(e) => Step::Next(Some(e)),
            _ => Step::Next(None),
        };
    }
    if let Some(e) = error.downcast_ref::<quarantine::Error>() {
        return match e {
            quarantine::Error::Sql(e) => sqlite(e.code),
            _ => Step::Next(None),
        };
    }
    if let Some(e) = error.downcast_ref::<radicle::cob::cache::Error>() {
        if let radicle::cob::cache::Error::Internal(e) = e {
            return sqlite(e.code);
        }
        return Step::Next(error.source());
    }
    if let Some(e) = error.downcast_ref::<driver::Error>() {
        if let driver::Error::Host(e) = e {
            return Step::Next(Some(e));
        }
        return Step::Next(error.source());
    }
    if let Some(e) = error.downcast_ref::<radicle::storage::Error>() {
        if let radicle::storage::Error::Refs(e) = e {
            return Step::Next(Some(e));
        }
        return Step::Next(error.source());
    }
    if let Some(e) = error.downcast_ref::<radicle::storage::refs::Error>() {
        if let radicle::storage::refs::Error::Git(e) = e {
            return Step::Next(Some(e));
        }
        return Step::Next(error.source());
    }
    Step::Next(error.source())
}

fn counted_if(counted: bool) -> Step<'static> {
    if counted {
        Step::Counted
    } else {
        Step::Next(None)
    }
}

/// An SQLite error's code: out of memory, or a leaf that isn't.
fn sqlite(code: Option<isize>) -> Step<'static> {
    counted_if(matches!(code, Some(SQLITE_NOMEM | SQLITE_IOERR_NOMEM)))
}

/// The end: [`LINE`], and exit 71, allocating nothing.
fn fail_stop() -> ! {
    fc_service::exit::fail_stop(Exit::OutOfMemory, LINE)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use radicle::git::raw::ErrorCode;

    use super::*;

    fn git(class: ErrorClass) -> GitError {
        GitError::new(ErrorCode::GenericError, class, "out of memory")
    }

    fn sqlite(code: isize) -> sqlite::Error {
        sqlite::Error {
            code: Some(code),
            message: Some("out of memory".into()),
        }
    }

    /// `SQLITE_FULL`: not memory.
    const FULL: isize = 13;

    /// libradicle's backstop, which [`check`] asks.
    fn counted(error: &libradicle::Error) -> bool {
        error.is_out_of_memory()
    }

    #[test]
    fn the_sqlite_codes_are_the_c_librarys() {
        assert_eq!(SQLITE_NOMEM, sqlite::ffi::SQLITE_NOMEM as isize);
        assert_eq!(SQLITE_IOERR_NOMEM, sqlite::ffi::SQLITE_IOERR_NOMEM as isize);
    }

    #[test]
    fn the_line_is_one_json_log_line() {
        let text = std::str::from_utf8(LINE).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(line["reason"], "out_of_memory");
        assert_eq!(text.matches('\n').count(), 1);
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn libgit2s_out_of_memory_is_counted_and_zlibs_isnt() {
        assert!(counted(&libradicle::Error::Git(git(ErrorClass::NoMemory))));
        // A corrupt object's inflate is `GIT_ERROR_ZLIB` too: the request's
        // error, never a crash (0008, "Pools and budgets").
        assert!(!counted(&libradicle::Error::Git(git(ErrorClass::Zlib))));
        assert!(!counted(&libradicle::Error::Git(git(ErrorClass::Odb))));
    }

    #[test]
    fn sqlites_out_of_memory_is_counted() {
        for code in [SQLITE_NOMEM, SQLITE_IOERR_NOMEM] {
            assert!(counted(&libradicle::Error::Sqlite(sqlite(code))), "{code}");
        }
        assert!(!counted(&libradicle::Error::Sqlite(sqlite(FULL))));
    }

    /// What libradicle has already made text isn't counted, whatever it
    /// says.
    #[test]
    fn text_isnt_counted() {
        assert!(!counted(&libradicle::Error::NodeThread(
            "out of memory".into()
        )));
        assert!(!counted(&libradicle::Error::Announce(
            "out of memory".into()
        )));
    }

    /// heartwood's own errors, which the service meets without libradicle,
    /// are counted borrowed, through their transparent variants and their
    /// sources.
    #[test]
    fn heartwoods_own_errors_are_counted_borrowed() {
        let nomem = || git(ErrorClass::NoMemory);
        let counted: Vec<Box<dyn StdError + 'static>> = vec![
            Box::new(driver::Error::Host(nomem())),
            Box::new(driver::Error::State(state::Error::Git(nomem()))),
            Box::new(driver::Error::State(state::Error::Sql(sqlite(
                SQLITE_NOMEM,
            )))),
            Box::new(driver::Error::Quarantine(quarantine::Error::Sql(sqlite(
                SQLITE_IOERR_NOMEM,
            )))),
            Box::new(driver::Error::Io(std::io::Error::other(nomem()))),
            Box::new(state::Error::Sql(sqlite(SQLITE_NOMEM))),
            Box::new(quarantine::Error::Sql(sqlite(SQLITE_NOMEM))),
            Box::new(radicle::cob::cache::Error::Internal(sqlite(SQLITE_NOMEM))),
            Box::new(radicle::storage::Error::Git(nomem())),
            Box::new(radicle::storage::Error::Refs(
                radicle::storage::refs::Error::Git(nomem()),
            )),
            Box::new(radicle::storage::Error::Io(std::io::Error::other(nomem()))),
            Box::new(libradicle::Error::Git(nomem())),
        ];
        for error in &counted {
            assert!(heartwood_counted(error.as_ref()), "{error:?}");
        }
        let not: Vec<Box<dyn StdError + 'static>> = vec![
            Box::new(driver::Error::Host(git(ErrorClass::Config))),
            Box::new(driver::Error::NotBegun),
            Box::new(driver::Error::State(state::Error::Git(git(
                ErrorClass::Zlib,
            )))),
            Box::new(quarantine::Error::Sql(sqlite(FULL))),
            Box::new(radicle::cob::cache::Error::Internal(sqlite(FULL))),
            Box::new(radicle::storage::Error::InvalidRef),
            Box::new(std::io::Error::other("out of memory")),
        ];
        for error in &not {
            assert!(!heartwood_counted(error.as_ref()), "{error:?}");
        }
    }
}
