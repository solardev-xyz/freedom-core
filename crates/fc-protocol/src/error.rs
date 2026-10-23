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
    // Service errors (design 0007, Errors).
    /// A service instance is retired, unknown or stopping: main's backend
    /// fails with `freedom-ipfs native node is not running`.
    Stopped,
    // The Radicle service's start (design 0008, Errors). Each ends the
    // process after its reply.
    /// Something exists at the Radicle home's `keys/radicle`: main runs the
    /// switch, then starts once more.
    KeyFilePresent,
    /// The sealed node key doesn't open with this process's key, or doesn't
    /// hold 32 bytes.
    BadSealedKey,
    /// A start step that needs the node's identity came before
    /// `rad.identity` succeeded.
    NoIdentity,
}

/// The `error` member of a response: a closed shape, so a member it
/// doesn't have makes the response malformed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    fn an_error_body_has_no_other_members() {
        let ok: Result<ErrorBody, _> =
            serde_json::from_str(r#"{"code":"network","message":"x","data":{"a":1}}"#);
        assert!(ok.is_ok());
        let extra: Result<ErrorBody, _> =
            serde_json::from_str(r#"{"code":"network","message":"x","unexpected":1}"#);
        assert!(extra.is_err());
    }

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

    #[test]
    fn radicle_start_codes_on_the_wire() {
        // Design 0008, Errors: the codes of the Radicle service's start.
        for (code, wire) in [
            (ErrorCode::KeyFilePresent, "key_file_present"),
            (ErrorCode::BadSealedKey, "bad_sealed_key"),
            (ErrorCode::NoIdentity, "no_identity"),
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

    #[test]
    fn service_codes_on_the_wire() {
        // Design 0007, Errors: `stopped` beside 0001's codes, which the
        // services share (`invalid_argument`, `deadline`, `cancelled`,
        // `busy`, `internal`, `storage`, `protocol_mismatch`).
        for (code, wire) in [
            (ErrorCode::Stopped, "stopped"),
            (ErrorCode::InvalidArgument, "invalid_argument"),
            (ErrorCode::Deadline, "deadline"),
            (ErrorCode::Cancelled, "cancelled"),
            (ErrorCode::Busy, "busy"),
            (ErrorCode::Internal, "internal"),
            (ErrorCode::Storage, "storage"),
            (ErrorCode::ProtocolMismatch, "protocol_mismatch"),
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
