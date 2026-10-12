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
