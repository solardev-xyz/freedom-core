//! The confinement point (the seam design 0010 expects; 0010 itself is the
//! user's decision, and this build applies no confinement).
//!
//! 0010 has each service confine itself once, on the main thread, **while
//! it is the process's only thread**: after its arguments, the environment
//! and the gate, with its directories open, and before anything starts a
//! thread or reads untrusted input. `main` keeps that order today, so
//! adopting 0010 is filling [`confine`] in:
//! - before it: the panic hook, hardening, the arguments, the environment
//!   ([`crate::env`]), the gate, and [`Grant::open`];
//! - after it: logging's writer, the connection's threads, the watchdogs,
//!   then the handshake.
//!
//! The grant is what 0010's rules would name: the Radicle home, read and
//! write, and the service's own `HOME` directory (0008, "Spawn and lock").

use std::io;
use std::path::{Path, PathBuf};

/// The directories the service may use.
#[derive(Debug)]
pub struct Grant {
    /// The canonical Radicle home, under the gate.
    pub home: PathBuf,
    /// The service's own `HOME` (0008: an empty directory the service
    /// owns), canonical.
    #[expect(dead_code, reason = "0010's rules name it, once the user decides 0010")]
    pub own_home: PathBuf,
}

impl Grant {
    /// The grant for `home` (already canonical, from the gate) and
    /// `own_home`; both must be directories.
    pub fn open(home: &Path, own_home: &Path) -> io::Result<Self> {
        let own_home = std::fs::canonicalize(own_home)?;
        for dir in [home, own_home.as_path()] {
            if !std::fs::metadata(dir)?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "not a directory",
                ));
            }
        }
        Ok(Self {
            home: home.to_path_buf(),
            own_home,
        })
    }
}

/// Confines the process to `grant`: nothing yet (0010 is undecided). With
/// the test hooks, it reports how many threads the process has here, so a
/// test proves the point is reached single-threaded.
pub fn confine(grant: &Grant) {
    let _ = grant;
    crate::testhooks::at_confinement_point();
}
