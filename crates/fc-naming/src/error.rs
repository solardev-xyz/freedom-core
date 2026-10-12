/// Why a name or parameter was refused. Messages follow the JS where the
/// JS has one, so callers that surface them keep their wording.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("ENS name is empty")]
    EmptyName,
    /// ENSIP-15 refused the name while the resolver normalized it: the
    /// normalizer's own message, as `fastNormalize` throws it.
    #[error("{0}")]
    Normalize(String),
    /// ENSIP-15 refused the name inside ethers' `namehash`/`dnsEncode`,
    /// which wrap the reason.
    #[error("invalid ENS name ({0})")]
    InvalidName(String),
    #[error("invalid ENS name; empty component")]
    EmptyComponent,
    #[error("label exceeds {0} bytes")]
    LabelTooLong(usize),
    #[error("name exceeds {0} bytes")]
    NameTooLong(usize),
    #[error("DNS encoded label cannot exceed 255")]
    LabelLimitTooLarge,
    #[error("Invalid ENS destination chain ID")]
    InvalidChainId,
}
