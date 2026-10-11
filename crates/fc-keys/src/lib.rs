//! Key derivation for Freedom: BIP-39 mnemonics, BIP-32 (secp256k1) and
//! SLIP-10 (Ed25519) derivation, and the path registry.
//!
//! This crate must reproduce freedom-browser's JS implementation exactly;
//! `vectors/` holds the contract. It does no I/O, and randomness is passed in.
//!
//! Secret material (mnemonic, seed, private keys) lives in types that zeroize
//! on drop and never print their contents.

mod ed25519;
mod error;
pub mod freedom;
pub mod kdf;
mod mnemonic;
mod path;
mod secp256k1;

pub use ed25519::{Ed25519Key, derive_ed25519};
pub use error::Error;
pub use mnemonic::{Mnemonic, Seed, WordCount, is_valid_mnemonic};
pub use path::{ChildIndex, DerivationPath};
pub use secp256k1::{Address, Secp256k1Key, derive_secp256k1};
