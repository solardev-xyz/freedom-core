//! Exit codes (sysexits.h values), which main reads to decide whether to
//! restart the core (design 0001, "Shutdown, crashes and parent death").

use crate::gate::GateError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Normal exit: shutdown, stdin EOF, parent gone.
    Ok,
    /// Bad command line.
    Usage,
    /// A bug.
    Internal,
    /// Storage failure or refused filesystem: don't restart.
    Storage,
    /// The gate is held by another process: don't restart.
    LockHeld,
    /// Protocol violation or handshake failure.
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
            | GateError::LockInsideIdentity
            | GateError::Moved
            | GateError::Storage(_) => Exit::Storage,
        }
    }
}
