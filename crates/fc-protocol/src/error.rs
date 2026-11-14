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
    /// A signature or a spend the core's approvals refuse (design 0012,
    /// API): `data.reason` says why (`no_token`, `unknown_token`,
    /// `expired`, `mismatch`, `no_rule`, `fee_check`, …).
    NotAuthorized,
    /// A write to a permission file main still writes, one not in
    /// `core.hello`'s `grant_moved` (design 0012, "The files"): nothing
    /// changed, and `data.store` names the store.
    NotMoved,
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
    /// A node's gate is held by another process: a Radicle identity write
    /// while the Radicle service runs (design 0008, "Identity changes").
    LockHeld,
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
    /// `rad.reconcile` failed outside any one repository: the dirty marker,
    /// the storage directory, the progress state or the quarantine record,
    /// or a temporary clone that can't be removed. `message` names the
    /// step.
    RecoveryFailed,
    /// `rad.start` failed: libradicle's start, whose message is its own, or
    /// a step of the service's before it.
    StartFailed,
    // The Radicle service's methods (design 0008, Errors).
    /// A read's libradicle error that today's message test takes for a
    /// missing thing (`not found`, `does not exist`, `NotFound`, in any
    /// case): its `message` is libradicle's (design 0008, Errors).
    NotFound,
    /// A libradicle error before a write has started, its `message` naming
    /// what failed.
    Failed,
    /// `rad.remove_repo`: no quarantine record of the repository has that
    /// `qid`, so nothing was removed (design 0008, "The escape").
    NotQuarantined,
    /// A write past its mutation start that isn't proven: its error, a
    /// panic, a cancel, its deadline, the stop or the node's end. It may
    /// have been recorded; main never retries it (design 0008, "Writes").
    OutcomeUnknown,
    /// A COB write on a node running with a throwaway key: a profile
    /// without a vault can't publish (design 0008, "Profiles without a
    /// vault").
    NeedsVault,
    /// A write to a quarantined repository, or a read of one: a COB read,
    /// or any read for a `namespace` quarantine; `data` holds its `kind`
    /// and `step` (design 0008, "The escape").
    Quarantined,
    /// `rad.blob`: its `range` is outside the blob, or the blob is empty;
    /// `data.size` holds the blob's size, for main's 416 with
    /// `Content-Range: bytes */size` (design 0008, "Ranges").
    RangeNotSatisfiable,
    /// `rad.import_repo`: the working copy's roots can't be granted (one
    /// fails main's check, or there are more roots or depth than the bound),
    /// so nothing is imported (design 0010, D5).
    UnsupportedLayout,
    /// No OS key store answered a key-store call, or the secrets file has
    /// no room for another item; `data.reason` says which (`timeout`,
    /// `unsupported`, `forget_backlog`, …), and the secret takes its
    /// fallback path (design 0013, API).
    KeyStoreUnavailable,
    /// The user cancelled the OS key store's prompt (design 0013, API).
    KeyStoreCancelled,
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
    fn lock_held_on_the_wire() {
        // Design 0008, Identity changes: a Radicle home's gate is held.
        assert_eq!(
            serde_json::to_value(ErrorCode::LockHeld).ok(),
            Some(serde_json::Value::from("lock_held"))
        );
    }

    #[test]
    fn radicle_start_codes_on_the_wire() {
        // Design 0008, Errors: the codes of the Radicle service's start.
        for (code, wire) in [
            (ErrorCode::KeyFilePresent, "key_file_present"),
            (ErrorCode::BadSealedKey, "bad_sealed_key"),
            (ErrorCode::NoIdentity, "no_identity"),
            (ErrorCode::RecoveryFailed, "recovery_failed"),
            (ErrorCode::StartFailed, "start_failed"),
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
    fn radicle_method_codes_on_the_wire() {
        // Design 0008, Errors, "The escape" and "Writes": a read's
        // libradicle error for a missing thing, any other libradicle error,
        // a removal whose `qid` no record has, a write past its start that
        // isn't proven, a COB write under a throwaway key, a write to a
        // quarantined repository, and a blob's range outside it.
        for (code, wire) in [
            (ErrorCode::NotFound, "not_found"),
            (ErrorCode::Failed, "failed"),
            (ErrorCode::NotQuarantined, "not_quarantined"),
            (ErrorCode::OutcomeUnknown, "outcome_unknown"),
            (ErrorCode::NeedsVault, "needs_vault"),
            (ErrorCode::Quarantined, "quarantined"),
            (ErrorCode::RangeNotSatisfiable, "range_not_satisfiable"),
            (ErrorCode::UnsupportedLayout, "unsupported_layout"),
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

    /// Design 0013, API: the key store's two codes.
    #[test]
    fn key_store_codes_on_the_wire() {
        for (code, wire) in [
            (ErrorCode::KeyStoreUnavailable, "key_store_unavailable"),
            (ErrorCode::KeyStoreCancelled, "key_store_cancelled"),
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

    /// Design 0012, API: an approvals refusal.
    #[test]
    fn not_authorized_on_the_wire() {
        assert_eq!(
            serde_json::to_value(ErrorCode::NotAuthorized).ok(),
            Some(serde_json::Value::from("not_authorized"))
        );
        assert_eq!(
            serde_json::from_value::<ErrorCode>("not_authorized".into()).ok(),
            Some(ErrorCode::NotAuthorized)
        );
    }

    /// Design 0012, "The files": a write to a file that hasn't moved.
    #[test]
    fn not_moved_on_the_wire() {
        assert_eq!(
            serde_json::to_value(ErrorCode::NotMoved).ok(),
            Some(serde_json::Value::from("not_moved"))
        );
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
