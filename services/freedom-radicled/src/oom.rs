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
//!   reaches the service's handling, [`check`] runs first, before it is
//!   answered, logged or swallowed, and so does [`check_heartwood`] for
//!   heartwood's own errors, which the service meets without libradicle:
//!   reconciliation's, the online repair's state and the quarantine
//!   record's. Either ends the process with 71 when libradicle's
//!   `Error::is_out_of_memory` counts the error, through
//!   `fc_service::exit::fail_stop`: no teardown runs, as none does after
//!   libradicle's hooks.
//! - **What it can't count** (0008, "Pools and budgets"): zlib's
//!   `deflateInit` refused for want of memory when libgit2 writes a loose
//!   object, which libgit2 reports as `GIT_ERROR_ZLIB`, as it does a corrupt
//!   object's inflate, so it stays the request's error; and an error that
//!   heartwood or libradicle has already made text, or wrapped in a type of
//!   its own that libradicle's walk can't see into (`Error::is_out_of_memory`
//!   lists them).

use fc_service::{Exit, log};
use serde_json::json;

/// Ends the process with 71 if `error` is, or wraps, an out-of-memory error
/// of libgit2's or SQLite's (see the module's doc). Otherwise it returns,
/// and the caller answers or logs `error` as before.
pub fn check(error: &libradicle::Error) {
    if counted(error) {
        fail_stop();
    }
}

/// [`check`], for an error of heartwood's own: counted as libradicle counts
/// what its `Error` wraps, carried in an `io::Error`, whose inner error
/// libradicle's walk follows. The caller has taken what it needs from
/// `error` first: its message, or its kind.
pub fn check_heartwood<E>(error: E)
where
    E: std::error::Error + Send + Sync + 'static,
{
    check(&carried(error));
}

/// Whether `error` is out of memory.
fn counted(error: &libradicle::Error) -> bool {
    error.is_out_of_memory()
}

/// `error`, in the `io::Error` that carries it to libradicle's walk.
fn carried<E>(error: E) -> libradicle::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    libradicle::Error::Io(std::io::Error::other(error))
}

/// The end: one line, and exit 71, with no teardown.
fn fail_stop() -> ! {
    fc_service::exit::fail_stop(Exit::OutOfMemory, || {
        log::error(
            "out of memory: the process ends",
            json!({ "reason": "out_of_memory" }),
        );
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use radicle::git::raw::{Error as GitError, ErrorClass, ErrorCode};
    use radicle::storage::git::reconcile::{driver, quarantine, state};

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

    /// `SQLITE_NOMEM`, and the extended `SQLITE_IOERR_NOMEM`.
    const NOMEM: isize = 7;
    const IOERR_NOMEM: isize = 3082;
    /// `SQLITE_FULL`: not memory.
    const FULL: isize = 13;

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
        for code in [NOMEM, IOERR_NOMEM] {
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
    /// are counted through their carrier as libradicle counts them.
    #[test]
    fn heartwoods_own_errors_are_counted_through_the_carrier() {
        let carried_counted = |error: libradicle::Error| counted(&error);
        assert!(carried_counted(carried(driver::Error::Host(git(
            ErrorClass::NoMemory
        )))));
        assert!(carried_counted(carried(driver::Error::State(
            state::Error::Git(git(ErrorClass::NoMemory))
        ))));
        assert!(carried_counted(carried(driver::Error::State(
            state::Error::Sql(sqlite(NOMEM))
        ))));
        assert!(carried_counted(carried(quarantine::Error::Sql(sqlite(
            NOMEM
        )))));
        assert!(carried_counted(carried(driver::Error::Quarantine(
            quarantine::Error::Sql(sqlite(IOERR_NOMEM))
        ))));
        // Not memory.
        assert!(!carried_counted(carried(driver::Error::Host(git(
            ErrorClass::Config
        )))));
        assert!(!carried_counted(carried(quarantine::Error::Sql(sqlite(
            FULL
        )))));
        assert!(!carried_counted(carried(driver::Error::NotBegun)));
        assert!(!carried_counted(carried(std::io::Error::other(
            "out of memory"
        ))));
    }
}
