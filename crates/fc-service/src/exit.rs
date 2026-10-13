//! Exit codes (sysexits.h values), which main reads to decide whether to
//! restart a service (designs 0001 and 0007, "Crashes, hangs and restarts").

use std::time::{Duration, Instant};

use crate::gate::GateError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Normal exit: shutdown, stdin EOF, a failed write to stdout, or the
    /// parent gone.
    Ok,
    /// Bad command line: don't restart.
    Usage,
    /// A bug, a panic outside request work, or a teardown that couldn't
    /// prove quiescence: a crash, restarted.
    Internal,
    /// Storage failure or refused filesystem: don't restart.
    Storage,
    /// The lock is held by another process: don't restart.
    LockHeld,
    /// A protocol violation, the handshake's deadline, or the writer stall:
    /// a crash, restarted.
    Protocol,
}

impl Exit {
    pub fn code(self) -> u8 {
        match self {
            Exit::Ok => 0,
            Exit::Usage => 64,
            Exit::Internal => 70,
            Exit::Storage => 74,
            Exit::LockHeld => 75,
            Exit::Protocol => 76,
        }
    }
}

impl Exit {
    /// The exit with `code`, if it is one of these.
    pub(crate) fn from_code(code: u8) -> Option<Exit> {
        [
            Exit::Ok,
            Exit::Usage,
            Exit::Internal,
            Exit::Storage,
            Exit::LockHeld,
            Exit::Protocol,
        ]
        .into_iter()
        .find(|exit| exit.code() == code)
    }
}

/// How long a fixed-time exit lets its report reach stderr.
pub(crate) const REPORT_BOUND: Duration = Duration::from_millis(150);

/// Ends the process with `exit`, after `report` and the log queue have had
/// at most `bound`.
///
/// The bound is armed first, on a thread of its own, so no exit waits on
/// stderr: if main stops draining it, a report blocked on the pipe (or on
/// stderr's lock, held by a log write blocked there) can't hold the process
/// up. If no thread can be started, the process exits at once, unreported.
pub(crate) fn exit_reporting(exit: Exit, bound: Duration, report: impl FnOnce()) -> ! {
    let code = i32::from(exit.code());
    let started = Instant::now();
    let armed = std::thread::Builder::new()
        .name("exit".into())
        .spawn(move || {
            std::thread::sleep(bound);
            std::process::exit(code)
        });
    if armed.is_ok() {
        report();
        crate::log::finish(bound.saturating_sub(started.elapsed()));
    }
    // Concurrent exits are serialized by std: the first one ends the
    // process.
    std::process::exit(code)
}

impl From<&GateError> for Exit {
    fn from(error: &GateError) -> Self {
        match error {
            GateError::Held => Exit::LockHeld,
            GateError::Unqualified(_)
            | GateError::LockInsideData
            | GateError::Moved
            | GateError::Storage(_) => Exit::Storage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_0001s() {
        let codes: Vec<u8> = [
            Exit::Ok,
            Exit::Usage,
            Exit::Internal,
            Exit::Storage,
            Exit::LockHeld,
            Exit::Protocol,
        ]
        .map(Exit::code)
        .to_vec();
        assert_eq!(codes, [0, 64, 70, 74, 75, 76]);
        for code in codes {
            assert_eq!(Exit::from_code(code).map(Exit::code), Some(code));
        }
        assert_eq!(Exit::from_code(1), None);
    }
}
