//! Error codes on the wire (design 0001, "Messages"). Main maps each code to
//! the exact JS string per method; see the design's parity table.

use serde::{Deserialize, Serialize};

/// A stable error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // Request errors.
    VaultLocked,
    IncorrectPassword,
    Throttled,
    NoVault,
    VaultExists,
    UnsupportedVaultVersion,
    CorruptVault,
    InvalidMnemonic,
    InvalidArgument,
    WeakPassword,
    Storage,
    NodeIdentityCorrupt,
    /// A thrown name resolution (design 0004, Replies).
    ResolutionFailed,
    /// A `chain.*` request failed with today's thrown error, tagged with its
    /// origin in `data.kind` (design 0005, Errors and text).
    ChainError,
    // Transport errors, main's terminal replies to `shell.*` requests
    // (design 0004, Transport errors). None carries a URL or server text.
    Timeout,
    Network,
    Refused,
    TooLarge,
    StaleGeneration,
    // Protocol-level.
    Forbidden,
    Busy,
    Cancelled,
    Deadline,
    /// A request spent its memory budget (design 0005, Bounds).
    Budget,
    /// The chain's configuration changed while the request ran: main sends
    /// a read or a fee quote again, once (design 0005, Generations).
    Reconfigured,
    ProtocolMismatch,
    UnknownMethod,
    Internal,
}

/// The `error` member of a response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ErrorBody {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_codes_on_the_wire() {
        // Design 0005, Errors and text: `chain_error` for today's thrown
        // errors; `budget` and `reconfigured` beside 0001's own codes.
        for (code, wire) in [
            (ErrorCode::ChainError, "chain_error"),
            (ErrorCode::Budget, "budget"),
            (ErrorCode::Reconfigured, "reconfigured"),
            (ErrorCode::TooLarge, "too_large"),
        ] {
            assert_eq!(
                serde_json::to_value(code).ok(),
                Some(serde_json::Value::from(wire))
            );
            assert_eq!(
                serde_json::from_value::<ErrorCode>(wire.into()).ok(),
                Some(code)
            );
        }
    }
}
