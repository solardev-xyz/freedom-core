//! Ethereum signing for Freedom with ethers v6 parity (design 0002):
//! EIP-155 and EIP-1559 transactions, EIP-191 messages and EIP-712 typed
//! data. `vectors/signing.json`, produced by the pinned JS, is the contract.
//!
//! Keys come in as `k256` signing keys borrowed from fc-keys and never leave.
//! The crate does no I/O.

mod address;
mod eip712;
mod error;
mod hex;
mod json;
pub mod rlp;
mod signature;
mod tx;
mod u256;

pub use address::{address_of, checksum_address, keccak256, parse_address};
pub use eip712::{TypedDataView, ViewRequest, typed_data_hash, typed_data_view};
pub use error::{Error, MAX_QUOTED_CHARS, MAX_QUOTED_NAMES, quoted, quoted_list, shortened};
pub use hex::{parse_bytes, to_hex};
pub use json::parse_json;
pub use signature::{eip191_digest, sign_digest, sign_message, sign_typed_data};
pub use tx::{PreparedTransaction, SignedTransaction, Transaction};
pub use u256::{U256, parse_signed, parse_unsigned};
