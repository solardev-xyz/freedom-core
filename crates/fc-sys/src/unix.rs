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
