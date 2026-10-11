//! Freedom's identity vault: the `identity-vault.json` format that
//! freedom-browser's `vault.js` reads and writes, and the vault's lock state
//! and unlock throttling.
//!
//! A logic crate: it does no I/O and reads no clock. Callers pass file
//! contents, passwords, randomness and the current time, and get back the
//! bytes to write.

mod error;
pub mod format;

pub use error::Error;
