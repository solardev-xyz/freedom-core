//! The wallet's stores in the core (design 0013, set A): PRF-5a,
//! `identity/vault-meta.json`, the wallet list and the vault's public
//! metadata ([`vault_meta`]); PRF-5e, the intent journal ([`intents`]);
//! PRF-5f, `safe-pending.json`, the pending Safe transactions
//! ([`safe_pending`], from `wallet/safe/pending-store.js`).
//!
//! The reference is freedom-browser's `src/main/identity-manager.js`;
//! `vectors/stores.json`, produced from it, is the contract (AGENTS rule 5).
//! Each operation here is one of that file's functions, step for step: the
//! same reads, the same refusals with the same messages and codes, and the
//! same text written after each, `JSON.stringify(…, null, 2)` in
//! JavaScript's property order with no trailing newline, so an older build
//! reads every file the core writes, and the core every file an older build
//! wrote.
//!
//! The crate does no I/O (AGENTS rule 2): a file comes in as its bytes and
//! goes out as its text, the clock as the caller's `now_ms`, and the
//! identity core's derived addresses through the caller's closures. The
//! durable write, the set-aside of an unreadable file and the one-writer
//! handover are `freedom-cored`'s.

mod address;
pub mod intents;
mod js;
pub mod payments;
pub mod safe_pending;
pub mod vault_meta;

pub use address::{
    address_bytes, is_address, normalize_address, normalized_bytes, value_address_bytes,
    value_normalize_address,
};
pub use fc_json::{JsString, JsValue};
