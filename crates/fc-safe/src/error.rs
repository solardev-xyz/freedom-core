//! What fc-safe refuses.

/// A Safe, SafeTx or SafeMessage fc-safe won't build, or signatures it
/// won't join.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Not one of the Safes Freedom creates (design 0016, Q24): another
    /// chain, or not 1 of 2 or 2 of 3 owners.
    #[error("Freedom's Safes are Safe 1.4.1 on Gnosis, 1 of 2 or 2 of 3: {0}")]
    Unsupported(&'static str),
    /// An owner list Safe's `setup` would refuse: an owner twice, the zero
    /// address or the owners' list sentinel (`0x…01`).
    #[error("invalid Safe owners: {0}")]
    Owners(&'static str),
    /// A salt that isn't decimal digits for a uint256 (the reference's
    /// "Invalid Safe salt nonce", or ethers' out-of-bounds refusal).
    #[error("Invalid Safe salt nonce")]
    Salt,
    /// A record whose address isn't the one its owners, threshold and salt
    /// derive (the reference's "Safe address mismatch").
    #[error("Safe address mismatch: record says {record}, init params derive {derived}")]
    AddressMismatch { record: String, derived: String },
    /// A SafeTx nonce above [`crate::MAX_NONCE`], which the reference
    /// can't hash (protocol-kit reads the nonce as a JS number, and ethers
    /// refuses one past 2^53 − 1) and safe-pending.json can't keep exactly.
    #[error("a Safe nonce above 2^53 - 1")]
    Nonce,
    /// SafeTx data longer than [`crate::MAX_DATA`].
    #[error("SafeTx data over {} bytes", crate::MAX_DATA)]
    DataTooLong,
    /// A SafeTx field other than Freedom's (design 0016, "Built and hashed
    /// in the core"): an operation but CALL, a gas field but 0, a gas token
    /// or refund receiver but the zero address.
    #[error("a SafeTx with another {0} than Freedom's")]
    Field(&'static str),
    /// SafeTx fields not in the shape the reference writes them.
    #[error("malformed SafeTx: {0}")]
    Malformed(&'static str),
    /// Typed data the core can't hash (`fc-evm`'s refusal).
    #[error("{0}")]
    TypedData(String),
    /// An owner's signature refused.
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// Fewer signatures than the threshold.
    #[error("Not enough signatures yet ({have} of {need})")]
    Threshold { have: usize, need: usize },
}

/// Why an owner's signature isn't kept (design 0016, "Owner signatures";
/// deviation `owner-signatures`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The signer isn't one of the Safe's owners.
    #[error("That account is not an owner of this Safe")]
    NotOwner,
    /// Not 65 bytes, `r ‖ s ‖ v`.
    #[error("an owner signature is 65 bytes")]
    Length,
    /// A `v` other than 27 or 28: Freedom makes no other kind, and a Safe
    /// reads 0 and 1 as a contract's and an approved hash's.
    #[error("an owner signature's v is 27 or 28")]
    V,
    /// No address recovers from it (fc-evm's rules: `s` low, `r` and `s`
    /// in range).
    #[error("invalid signature")]
    Recovery,
    /// It recovers to another address than the owner's.
    #[error("the signature is not this owner's")]
    Mismatch,
}

impl Error {
    /// The kind `vectors/safe.json` names a refusal by.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Unsupported(_) => "unsupported",
            Error::Owners(_) => "owners",
            Error::Salt => "salt",
            Error::AddressMismatch { .. } => "address_mismatch",
            Error::Nonce => "nonce",
            Error::DataTooLong => "data",
            Error::Field(_) => "field",
            Error::Malformed(_) => "malformed",
            Error::TypedData(_) => "typed_data",
            Error::Signature(error) => error.kind(),
            Error::Threshold { .. } => "threshold",
        }
    }
}

impl SignatureError {
    /// The kind `vectors/safe.json` names a refusal by.
    pub fn kind(&self) -> &'static str {
        match self {
            SignatureError::NotOwner => "not_owner",
            SignatureError::Length => "length",
            SignatureError::V => "v",
            SignatureError::Recovery => "recovery",
            SignatureError::Mismatch => "mismatch",
        }
    }
}
