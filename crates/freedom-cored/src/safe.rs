//! Freedom's Safes in the daemon (design 0016, SAFE-2). `fc-safe` builds,
//! hashes and judges; this module makes its chain reads and, from S2 on,
//! serves the `safe.*` methods.
//!
//! - [`evidence`] (S1): the eight setup reads through the chain machine,
//!   each verified, and the setup check on their answers.
//! - [`methods`] (S2): `safe.create`, `.status`, `.deploy`, `.deployed`,
//!   `.pending` and `.discard`.

pub mod evidence;
pub mod methods;
