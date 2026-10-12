/// Why an input can't be signed. Messages describe the input, never a key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid transaction: {0}")]
    Transaction(String),
    #[error("invalid typed data: {0}")]
    TypedData(String),
    #[error("invalid {0}")]
    Value(String),
    #[error("signing failed")]
    Signing,
}
