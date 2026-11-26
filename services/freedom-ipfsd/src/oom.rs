//! Out of memory under the memory cap (design 0010, "The memory cap"; 0007,
//! "Errors"): a native library's out-of-memory error ends the process with
//! exit 71 (`out_of_memory`), and no request is answered with it. Main
//! restarts the process as after a crash.
//!
//! - **SQLite's allocator** ends the process itself. `main` installs
//!   freedom-ipfs-store's hook ([`freedom_ipfs_store::fail_stop_on_oom`])
//!   first, so an allocation SQLite can't make exits 71 at once, with the
//!   store's line on stderr ([`freedom_ipfs_store::OUT_OF_MEMORY_LINE`]),
//!   before any statement fails with it.
//! - **What is left** is an out-of-memory error SQLite reports without its
//!   allocator failing: a size past its allocation limit, or a heap limit,
//!   neither of which the store's statements reach. Where a store error
//!   reaches the service, at the store's open (`ipfs.start`) and in
//!   `ipfs.stats`, [`exit_on`] ends the process with 71 for one
//!   ([`StoreError::is_out_of_memory`]), in place of the reply.
//! - **Requests** get no store error: the gateway answers with heads, and a
//!   body's failure is text. The hook is what covers them.
//! - **Rust's allocator** aborts the process on a failed allocation, as it
//!   does by default.

use std::time::Duration;

use fc_service::{Exit, log};
use freedom_ipfs_store::StoreError;
use serde_json::json;

use crate::instances::store_error_kind;

/// How long the exit's line gets to reach stderr.
const REPORT: Duration = Duration::from_millis(150);

/// Ends the process with exit 71 if `error` is out of memory, from where
/// `at` names; returns otherwise.
pub fn exit_on(error: &StoreError, at: &'static str) {
    if error.is_out_of_memory() {
        exit(at, store_error_kind(error));
    }
}

/// Ends the process with exit 71, logging where (`at`) and the error's
/// fixed name. The first exit to begin wins ([`fc_service::exit::claim`]):
/// if another has, it ends the process, and this thread waits for it.
fn exit(at: &'static str, error: &'static str) -> ! {
    fc_service::exit::claim();
    log::error(
        "out of memory: the process ends",
        json!({ "at": at, "error": error, "exit": Exit::OutOfMemory.code() }),
    );
    log::finish(REPORT);
    std::process::exit(i32::from(Exit::OutOfMemory.code()))
}

#[cfg(test)]
mod tests {
    use fc_service::Exit;

    /// The store's hook exits with the code main reads as `out_of_memory`.
    #[test]
    fn the_stores_exit_is_the_services() {
        assert_eq!(
            freedom_ipfs_store::OUT_OF_MEMORY_EXIT,
            i32::from(Exit::OutOfMemory.code())
        );
        assert_eq!(Exit::OutOfMemory.code(), 71);
    }
}
