//! Unix calls shared by Linux and macOS confinement (design 0010).

use std::io;

/// Marks descriptor `fd` close-on-exec (`fcntl(fd, F_SETFD, FD_CLOEXEC)`):
/// the entry's re-exec drops it (design 0010, step 1), on Linux before
/// 5.11 and always on macOS, which has no `close_range`. Closes nothing.
/// `EBADF` if `fd` isn't open.
#[allow(unsafe_code)]
pub fn set_cloexec(fd: i32) -> io::Result<()> {
    // SAFETY: fcntl with F_SETFD takes a descriptor number and an integer,
    // reads no memory, and only sets the descriptor's flags, of which
    // FD_CLOEXEC is the one there is: it closes nothing.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Ends the process at once with `code`, after one write of `line` to
/// standard error: a fail-stop that allocates nothing, takes no lock,
/// starts no thread and runs no `atexit` handler, destructor or flush, so
/// that it works with the heap exhausted (design 0010, "The memory cap": a
/// service's out-of-memory backstop, as libradicle's hooks end the process).
/// A short or failed write is ignored: the exit code is what the parent
/// reads.
pub fn fail_stop(code: i32, line: &'static [u8]) -> ! {
    write_stderr(line);
    exit_now(code)
}

/// One `write(2, line)`.
#[allow(unsafe_code)]
fn write_stderr(line: &'static [u8]) {
    // SAFETY: write reads at most `line.len()` bytes from `line`, a live
    // static buffer of that length, and touches no other memory of ours;
    // descriptor 2 is only written to, and a closed one fails harmlessly.
    let _ = unsafe { libc::write(2, line.as_ptr().cast(), line.len()) };
}

/// `_exit(code)`: the process ends here, with no handler run.
#[allow(unsafe_code)]
fn exit_now(code: i32) -> ! {
    // SAFETY: `_exit` takes an integer and never returns: the process ends
    // at once, so no invariant of it can be observed broken after.
    unsafe { libc::_exit(code) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marking_close_on_exec_closes_nothing() {
        use std::io::{Read, Seek, Write};
        use std::os::fd::AsRawFd;
        let path = std::env::temp_dir().join(format!("fc-sys-cloexec-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let _ = std::fs::remove_file(&path);
        set_cloexec(file.as_raw_fd()).unwrap();
        file.write_all(b"still mine").unwrap();
        file.rewind().unwrap();
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text, "still mine");
        assert!(set_cloexec(1 << 20).is_err());
    }
}
