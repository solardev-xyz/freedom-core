//! Broadcast attempts (design 0005, Broadcast → Attempts and Refusals). The
//! reference has no such classifier: its broadcast re-sends to every
//! endpoint on any error and reports the last one. This is the design's
//! (deviation `broadcast-outcome`), and its vectors are the design's.
//!
//! A node's error is a **refusal** only when its code is one the client
//! documents for it and its message starts with that client's wording of a
//! fixed txpool rejection. Anything else is ambiguous: the bytes may be out
//! there. `already known` is never a refusal, in any client's wording: it
//! says the bytes exist.
//!
//! The wordings, with each client's source at the release cited (fetched
//! 2026-10-12):
//! - **geth v1.17.8:** `core/txpool/errors.go`, `core/error.go` and
//!   `core/txpool/validation.go`, which wraps them (`nonce too low: next
//!   nonce 5, tx nonce 3`); `invalid sender: invalid chain id for signer`
//!   (`core/types/transaction_signing.go`); code `-32000`
//!   (`rpc/errors.go`, `errcodeDefault`).
//! - **Nethermind 2.1.0:** geth's phrases (`Nethermind.TxPool/
//!   TxPoolErrorMessages.cs`, `Nethermind.Core/Messages/TxErrorMessages.cs`)
//!   and its own (`transaction too large`, `unsupported transaction type`,
//!   `failed to recover sender`, `gas limit reached`, `transaction invalid,
//!   <validation>`), as `AcceptTxResult.ToString()`: the phrase, then `, `
//!   and details. Code `-32000` (`JsonRpc/ErrorCodes.cs`
//!   `TransactionRejected`).
//! - **Nethermind 1.x:** the result's `nameof()` (`InsufficientFunds`,
//!   `FeeTooLow`, `ReplacementNotAllowed`, ...) except `nonce too low` and
//!   `gas limit reached` (1.39.3 `AcceptTxResult.cs`); code `-32010` up to
//!   1.36 and `-32000` from 1.37.0.
//! - **Erigon v3.7.1:** `<import result>: <discard reason>`
//!   (`rpc/jsonrpc/send_transaction.go`, `txnprovider/txpool/
//!   txpool_grpc_server.go`, `txpoolcfg/txpoolcfg.go`), and `invalid chain
//!   id, expected: <n> got: <n>`; code `-32000`.
//! - **Besu 26.9.0:** fixed messages, each with its own code
//!   (`JsonRpcErrorConverter.java`, `RpcErrorType.java`).
//! - **reth v2.7.0:** geth's phrases (`crates/rpc/rpc-eth-types/src/error/
//!   mod.rs`), `invalid chain ID`; code `-32000`, or `-32003` (alloy's
//!   `TransactionRejected`) for insufficient funds, an unsupported type and
//!   a tip above the fee cap.
//! - **Providers** (Base's and Alchemy's references) answer with geth's
//!   wording.

use fc_json::index::{Index, Kind};

use crate::answer::{Answer, AnswerError, Outcome};
use crate::txhash::TxHash;

/// The txpool rejections the design counts as refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    InsufficientFunds,
    NonceTooLow,
    ReplacementUnderpriced,
    Underpriced,
    IntrinsicGasTooLow,
    ExceedsBlockGasLimit,
    FeeCapBelowBaseFee,
    TipAboveFeeCap,
    InvalidSender,
    InvalidChainId,
    OversizedData,
    TransactionTypeNotSupported,
}

impl RefusalReason {
    /// The reason's name in the vectors.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InsufficientFunds => "insufficient_funds",
            Self::NonceTooLow => "nonce_too_low",
            Self::ReplacementUnderpriced => "replacement_underpriced",
            Self::Underpriced => "underpriced",
            Self::IntrinsicGasTooLow => "intrinsic_gas_too_low",
            Self::ExceedsBlockGasLimit => "exceeds_block_gas_limit",
            Self::FeeCapBelowBaseFee => "fee_cap_below_base_fee",
            Self::TipAboveFeeCap => "tip_above_fee_cap",
            Self::InvalidSender => "invalid_sender",
            Self::InvalidChainId => "invalid_chain_id",
            Self::OversizedData => "oversized_data",
            Self::TransactionTypeNotSupported => "transaction_type_not_supported",
        }
    }
}

use RefusalReason as R;

/// geth's phrases: geth, Nethermind 2, reth and the providers; Nethermind
/// up to 1.36 sends `nonce too low` with `-32010`, reth some with `-32003`.
const GETH_CODES: &[i64] = &[-32000, -32003, -32010];
/// Nethermind's own wordings.
const NETHERMIND_CODES: &[i64] = &[-32000, -32010];
const ERIGON_CODES: &[i64] = &[-32000];

/// `(codes, message prefix, reason)`.
const REFUSALS: &[(&[i64], &str, RefusalReason)] = &[
    // geth's phrases.
    (GETH_CODES, "insufficient funds", R::InsufficientFunds),
    (GETH_CODES, "nonce too low", R::NonceTooLow),
    (
        GETH_CODES,
        "replacement transaction underpriced",
        R::ReplacementUnderpriced,
    ),
    (GETH_CODES, "transaction underpriced", R::Underpriced),
    (GETH_CODES, "intrinsic gas too low", R::IntrinsicGasTooLow),
    (
        GETH_CODES,
        "exceeds block gas limit",
        R::ExceedsBlockGasLimit,
    ),
    (
        GETH_CODES,
        "max fee per gas less than block base fee",
        R::FeeCapBelowBaseFee,
    ),
    (
        GETH_CODES,
        "max priority fee per gas higher than max fee per gas",
        R::TipAboveFeeCap,
    ),
    (GETH_CODES, "invalid sender", R::InvalidSender),
    // Erigon's RPC check, then reth's.
    (GETH_CODES, "invalid chain id", R::InvalidChainId),
    (GETH_CODES, "invalid chain ID", R::InvalidChainId),
    (GETH_CODES, "oversized data", R::OversizedData),
    (
        GETH_CODES,
        "transaction type not supported",
        R::TransactionTypeNotSupported,
    ),
    // Nethermind 2.
    (
        NETHERMIND_CODES,
        "gas limit reached",
        R::ExceedsBlockGasLimit,
    ),
    (NETHERMIND_CODES, "transaction too large", R::OversizedData),
    (
        NETHERMIND_CODES,
        "unsupported transaction type",
        R::TransactionTypeNotSupported,
    ),
    (
        NETHERMIND_CODES,
        "failed to recover sender",
        R::InvalidSender,
    ),
    (
        NETHERMIND_CODES,
        "transaction invalid, InvalidTxChainId",
        R::InvalidChainId,
    ),
    (
        NETHERMIND_CODES,
        "transaction invalid, InvalidTxSignature",
        R::InvalidSender,
    ),
    (
        NETHERMIND_CODES,
        "transaction invalid, intrinsic gas too low",
        R::IntrinsicGasTooLow,
    ),
    // Nethermind 1.
    (NETHERMIND_CODES, "InsufficientFunds", R::InsufficientFunds),
    (NETHERMIND_CODES, "FeeTooLow", R::Underpriced),
    (
        NETHERMIND_CODES,
        "ReplacementNotAllowed",
        R::ReplacementUnderpriced,
    ),
    (NETHERMIND_CODES, "MaxTxSizeExceeded", R::OversizedData),
    (
        NETHERMIND_CODES,
        "NotSupportedTxType",
        R::TransactionTypeNotSupported,
    ),
    (NETHERMIND_CODES, "FailedToResolveSender", R::InvalidSender),
    (
        NETHERMIND_CODES,
        "Invalid, InvalidTxChainId",
        R::InvalidChainId,
    ),
    (
        NETHERMIND_CODES,
        "Invalid, InvalidTxSignature",
        R::InvalidSender,
    ),
    (
        NETHERMIND_CODES,
        "Invalid, intrinsic gas too low",
        R::IntrinsicGasTooLow,
    ),
    // Erigon.
    (
        ERIGON_CODES,
        "INTERNAL_ERROR: nonce too low",
        R::NonceTooLow,
    ),
    (
        ERIGON_CODES,
        "INTERNAL_ERROR: insufficient funds",
        R::InsufficientFunds,
    ),
    (
        ERIGON_CODES,
        "INTERNAL_ERROR: IntrinsicGas",
        R::IntrinsicGasTooLow,
    ),
    (
        ERIGON_CODES,
        "INTERNAL_ERROR: gas limit is too high",
        R::ExceedsBlockGasLimit,
    ),
    (ERIGON_CODES, "FEE_TOO_LOW: underpriced", R::Underpriced),
    (
        ERIGON_CODES,
        "FEE_TOO_LOW: replacement transaction underpriced",
        R::ReplacementUnderpriced,
    ),
    (ERIGON_CODES, "INVALID: invalid sender", R::InvalidSender),
    (ERIGON_CODES, "INVALID: oversized data", R::OversizedData),
    (
        ERIGON_CODES,
        "INVALID: fork supporting this transaction type is not activated yet",
        R::TransactionTypeNotSupported,
    ),
    (
        ERIGON_CODES,
        "INVALID: max priority fee per gas higher than max fee per gas",
        R::TipAboveFeeCap,
    ),
    // Besu.
    (&[-32001], "Nonce too low", R::NonceTooLow),
    (
        &[-32004],
        "Upfront gas cost exceeds account balance",
        R::InsufficientFunds,
    ),
    (
        &[-32004],
        "Insufficient funds for transfer",
        R::InsufficientFunds,
    ),
    (
        &[-32003],
        "Intrinsic gas exceeds gas limit",
        R::IntrinsicGasTooLow,
    ),
    (
        &[-32005],
        "Transaction gas limit exceeds block gas limit",
        R::ExceedsBlockGasLimit,
    ),
    (
        &[-32009],
        "Gas price below configured minimum gas price",
        R::Underpriced,
    ),
    (
        &[-32009],
        "Gas price below current base fee",
        R::FeeCapBelowBaseFee,
    ),
    (
        &[-32000],
        "Replacement transaction underpriced",
        R::ReplacementUnderpriced,
    ),
    (
        &[-32000],
        "Max priority fee per gas exceeds max fee per gas",
        R::TipAboveFeeCap,
    ),
    (&[-32002], "Invalid signature", R::InvalidSender),
    (&[-32000], "Wrong chainId", R::InvalidChainId),
    (
        &[-32000],
        "Transaction size exceeds the maximum allowed size",
        R::OversizedData,
    ),
    (
        &[-32602],
        "Invalid transaction type",
        R::TransactionTypeNotSupported,
    ),
];

/// Each client's `already known`: never a refusal.
const ALREADY_KNOWN: [&str; 4] = [
    "already known",
    "AlreadyKnown",
    "Known transaction",
    "ALREADY_EXISTS",
];

/// Whether a node's error, as the core parsed it from the answer (its
/// `code` as JSON text, `None` when absent, and its message), refuses the
/// transaction.
pub fn broadcast_refusal(code: Option<&str>, message: &[u16]) -> Option<RefusalReason> {
    let starts_with = |prefix: &str| {
        let mut units = message.iter();
        prefix
            .encode_utf16()
            .all(|unit| units.next() == Some(&unit))
    };
    if ALREADY_KNOWN.iter().any(|prefix| starts_with(prefix)) {
        return None;
    }
    let index = Index::new(code?).ok()?;
    let code = index.root();
    if code.kind() != Kind::Number {
        return None;
    }
    let code = code.number();
    REFUSALS
        .iter()
        .find(|(codes, prefix, _)| codes.iter().any(|&c| c as f64 == code) && starts_with(prefix))
        .map(|(_, _, reason)| *reason)
}

/// What one Direct attempt proves (design 0005, Attempts). The machine adds
/// `not sent` for an exchange main proves it never made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptClass {
    /// The answer is the transaction's own hash, any hex case.
    Accepted,
    /// A node error matching a refusal.
    Refused(RefusalReason),
    /// Anything else: another node error, another or no hash, a non-2xx
    /// status, an answer that isn't JSON.
    Ambiguous,
}

/// The class of a Direct attempt's answer, as [`crate::decode_answer`] read
/// it.
pub fn classify_broadcast_answer(
    hash: &TxHash,
    answer: &Result<Answer, AnswerError>,
) -> AttemptClass {
    let Ok(answer) = answer else {
        return AttemptClass::Ambiguous;
    };
    match answer.outcome() {
        Outcome::Result(Some(result)) if TxHash::from_json(result) == Some(*hash) => {
            AttemptClass::Accepted
        }
        Outcome::NodeError(error) => broadcast_refusal(error.code, error.message.units())
            .map_or(AttemptClass::Ambiguous, AttemptClass::Refused),
        Outcome::Result(_) => AttemptClass::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(code: &str, message: &str) -> Option<RefusalReason> {
        broadcast_refusal(Some(code), &message.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn exact_predicates() {
        assert_eq!(
            refusal("-32000", "nonce too low: next nonce 5, tx nonce 3"),
            Some(R::NonceTooLow)
        );
        assert_eq!(refusal("-32000", "already known"), None);
        assert_eq!(refusal("-32001", "Nonce too low"), Some(R::NonceTooLow));
        assert_eq!(refusal("-32000", "Nonce too low"), None);
        assert_eq!(refusal("\"-32000\"", "nonce too low"), None);
        assert_eq!(refusal("-32000", "nonce too lo"), None);
        assert_eq!(broadcast_refusal(None, &[]), None);
        for (_, prefix, _) in REFUSALS {
            assert!(
                !ALREADY_KNOWN.iter().any(|known| prefix.starts_with(known)),
                "{prefix}"
            );
        }
    }
}
