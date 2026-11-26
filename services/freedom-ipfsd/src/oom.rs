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
//!
//! **Nothing on the way out allocates,** since the heap may be exhausted:
//! the error is classified borrowed, by a `match`, and the exit writes a
//! static line with std's unbuffered stderr, then calls
//! `std::process::exit`. No line is formatted, no JSON is built, and the log
//! queue isn't used.

use std::io::Write;

use fc_service::Exit;
use freedom_ipfs_store::StoreError;

/// Where an out-of-memory error reached the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    /// The store's open, in `ipfs.start`'s build.
    StoreOpen,
    /// `ipfs.stats`' store figures.
    Stats,
}

impl At {
    /// The exit's line for here: static, so nothing is formatted.
    pub fn line(self) -> &'static [u8] {
        match self {
            At::StoreOpen => b"freedom-ipfsd: out of memory at the store's open; exiting 71\n",
            At::Stats => b"freedom-ipfsd: out of memory in ipfs.stats; exiting 71\n",
        }
    }
}

/// Ends the process with exit 71 if `error` is out of memory, from where
/// `at` names; returns otherwise. Allocates nothing either way.
pub fn exit_on(error: &StoreError, at: At) {
    if error.is_out_of_memory() {
        exit(at);
    }
}

/// Ends the process with exit 71, after `at`'s line. The first exit to
/// begin wins ([`fc_service::exit::claim`]): if another has, it ends the
/// process, and this thread waits for it.
fn exit(at: At) -> ! {
    fc_service::exit::claim();
    // Unbuffered, and its lock is a static one: a short or failed write is
    // ignored, since the exit code is what main reads.
    let _ = std::io::stderr().write_all(at.line());
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
