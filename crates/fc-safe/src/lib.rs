//! Freedom's Safes in the core (design 0016, SAFE-1): exactly the Safes
//! Freedom creates (Q24), Safe 1.4.1 on Gnosis, 1 of 2 or 2 of 3 of the
//! user's own accounts, with no setup call, payment, module or guard and
//! the canonical fallback handler.
//!
//! - [`constants`]: the pinned deployment, as safe-deployments 1.37.66 lists
//!   it, and the factory's proxy code (F-4).
//! - [`Setup`] and [`parse_salt`]: the Safe's address (CREATE2) and its
//!   deployment, computed with no chain read.
//! - [`SafeTx`] and [`SafeMessage`]: their typed data, in the reference's
//!   property order, and their hashes, through `fc-evm`.
//! - [`OwnerSignature`] and [`Signatures`]: an owner's signature checked (65
//!   bytes, `v` 27 or 28, recovered to that owner, an owner of the Safe) and
//!   the signatures joined, once each, sorted by owner.
//! - [`exec_transaction`]: `execTransaction`'s calldata, and [`NonceState`],
//!   a pending SafeTx against the Safe's nonce.
//!
//! The reference is freedom-browser's `src/main/wallet/safe/`, over
//! protocol-kit 8.0.11; `vectors/safe.json`, produced from it, is the
//! contract (AGENTS rule 5). What differs from it is design 0016's
//! `owner-signatures` (the reference keeps any signature ethers recovers to
//! the owner: `v` 0, 1 or an EIP-155 `v`, or 64 bytes) and `nonce-behind`
//! (it executes a SafeTx whose nonce is past the Safe's).
//!
//! The crate does no I/O: the chain's answers (the Safe's nonce) come in as
//! parameters.

pub mod constants;
mod error;
mod message;
mod setup;
mod signatures;
mod tx;

pub use error::{Error, SignatureError};
pub use message::SafeMessage;
pub use setup::{Deployment, Setup, check_chain, parse_salt};
pub use signatures::{OwnerSignature, Signatures};
pub use tx::{MAX_DATA, MAX_NONCE, NonceState, SafeTx, exec_transaction};

/// The first four bytes of a function's keccak256 signature hash.
fn selector(signature: &str) -> [u8; 4] {
    let hash = fc_evm::keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// A word holding a 20-byte address.
fn address_word(address: &[u8; 20]) -> [u8; 32] {
    fc_naming::abi::word_from_address(address)
}

/// `selector ‖ abi.encode(tokens)`.
fn call(signature: &str, tokens: &[fc_naming::abi::Token<'_>]) -> Vec<u8> {
    let mut data = selector(signature).to_vec();
    data.extend(fc_naming::abi::encode(tokens));
    data
}
