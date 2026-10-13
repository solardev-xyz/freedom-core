//! Exit codes (sysexits.h values), which main reads to decide whether to
//! restart a service (designs 0001 and 0007, "Crashes, hangs and restarts").

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
    }
}
