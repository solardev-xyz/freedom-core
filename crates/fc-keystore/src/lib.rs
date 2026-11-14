//! The key store (design 0013, 5.4a). This step, PRF-1a: the logic.
//!
//! - [`KeyStore`]: the trait the OS key stores sit behind, which makes and
//!   keeps 32-byte wrapping keys under one of two [`Policy`]s. On desktop
//!   the core's implementation sends each call to main, which runs it in a
//!   one-shot helper, `freedom-cored keystore` (PRF-1b); mobile implements
//!   it in the app, through `freedom-mobile-ffi`.
//! - [`SecretsFile`]: the profile's secrets file, every secret AES-256-GCM
//!   under such a key, with the items the profile still names (each key in
//!   use, each `pending` one and the `forget` list), its text, and every
//!   change to it as a function from one file to the next.
//!
//! The crate does no I/O (AGENTS rule 2): randomness comes in as the
//! caller's RNG, the file as its bytes, and the key store as the trait.
//! Writing the file atomically, asking the key store, and retrying a
//! `forget` are the caller's.
//!
//! No reference exists: `vectors/secrets.json` is the design's, written by
//! its generator (`vectors/generator/secrets.js`) under fixed keys and
//! nonces, and this crate replays it byte for byte.

mod file;
mod keystore;

pub use file::{
    AAD_LABEL, Binding, EntryName, MAX_BINDING_MEMBERS, MAX_BINDING_NAME_BYTES,
    MAX_BINDING_VALUE_BYTES, MAX_ENTRIES, MAX_FILE_BYTES, MAX_ITEMS, MAX_NAME_BYTES,
    MAX_SECRET_BYTES, Malformed, NONCE_BYTES, NamedItem, OpenError, Put, Refused, Secret,
    SecretsFile, TAG_BYTES, VERSION, associated_data,
};
pub use keystore::{
    Backend, BackendError, Blob, Capabilities, ItemId, KeyStore, KeyStoreError, Label,
    MAX_BLOB_BYTES, Policy, Randomness, Reason, Sealed, SealedForm, UnavailableReason, WrapKey,
};

#[cfg(test)]
mod tests;
