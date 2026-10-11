/// Vault errors. None carries secret material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The file or payload isn't the expected JSON or encoding.
    #[error("corrupt vault: {0}")]
    Corrupt(&'static str),
    /// `version` isn't 1. Holds the value as JS would print it.
    #[error("Unsupported vault version: {0}")]
    UnsupportedVersion(String),
    /// AES-GCM authentication failed, which passworder reports for a wrong
    /// password and for any tampering alike.
    #[error("Incorrect password")]
    IncorrectPassword,
    /// The vault decrypted, but the phrase inside isn't a valid mnemonic.
    #[error("Decrypted data is not a valid mnemonic")]
    InvalidDecryptedMnemonic,
    /// The caller passed parameters this crate refuses (iteration count,
    /// time range).
    #[error("invalid parameters: {0}")]
    InvalidParams(&'static str),
    /// The operation needs an unlocked vault (`VAULT_LOCKED_MESSAGE`).
    #[error("Vault is locked")]
    Locked,
    /// A lock or another unlock happened after this unlock's ticket was
    /// taken; the prepared secrets were wiped, not installed.
    #[error("unlock revoked by a later lock")]
    Revoked,
    /// The generation counter is exhausted (2^64 locks and unlocks).
    #[error("vault generation counter exhausted")]
    Exhausted,
    /// Key derivation failed.
    #[error("key derivation: {0}")]
    Keys(fc_keys::Error),
    /// The random number generator failed.
    #[error("random number generator failed")]
    Randomness,
    /// A bug: an operation that cannot fail did.
    #[error("internal error: {0}")]
    Internal(&'static str),
}
