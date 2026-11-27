//! Freedom's Safes in the daemon (design 0016, SAFE-2). `fc-safe` builds,
//! hashes and judges; this module makes its chain reads and, from S2 on,
//! serves the `safe.*` methods.
//!
//! - [`evidence`] (S1): the eight setup reads through the chain machine,
//!   each verified, and the setup check on their answers.
//! - [`methods`] (S2 to S6): `safe.create`, `.status`, `.deploy`,
//!   `.deployed`, `.pending` and `.discard`; `safe.prepare` and
//!   `.propose`; `safe.execute` and `.executed`, the executor's prepared
//!   send and its `executor-send` token; a page's Safe message,
//!   `safe.message_start`, `_sign`, `_state`, `_cancel` and `_complete`,
//!   its vault owners signing in the core; and the owners who sign later,
//!   `safe.sign_owner` for a pending SafeTx, a Ledger owner on the device
//!   lane, as `safe.message_sign`'s for a SafeMessage (S6).
//! - [`tx`] (S3): the SafeTx `safe.prepare` builds and keeps, its token's
//!   payload (D6), and the vault owners' signatures.
//! - [`entry`] (S3): a pending SafeTx's entry in `safe-pending.json`,
//!   written as the reference writes it and checked when it is read.

pub mod entry;
pub mod evidence;
pub mod methods;
pub mod tx;
