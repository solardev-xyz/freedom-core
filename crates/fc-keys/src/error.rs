/// Errors from key derivation. None of them carries secret material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Not a valid English BIP-39 mnemonic (word count, unknown word,
    /// spacing, or checksum).
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    /// Entropy must be 16, 20, 24, 28 or 32 bytes.
    #[error("invalid entropy length: {0} bytes")]
    InvalidEntropyLength(usize),
    /// A derivation path string is malformed.
    #[error("invalid derivation path")]
    InvalidPath,
    /// A derivation index must be below 2^31.
    #[error("derivation index out of range: {0}")]
    IndexOutOfRange(u64),
    /// SLIP-10 Ed25519 derivation supports hardened indices only.
    #[error("Ed25519 derivation requires hardened indices")]
    NonHardenedEd25519,
    /// The random number generator failed.
    #[error("random number generator failed")]
    Randomness,
    /// BIP-32 derivation failed (an invalid child key; probability ~2^-127).
    #[error("BIP-32 derivation failed")]
    Derivation,
}
