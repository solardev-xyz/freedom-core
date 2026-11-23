//! freedom-colibrid: Colibri's verifier as a native process (design 0014).
//!
//! - COL-2: the native, verifier-only C core, built from the pinned fork
//!   commit (see `Cargo.toml`), and a replay of every COL-1 trace through
//!   it (`tests/replay.rs`).
//! - COL-4: the service (`src/main.rs`): the connection's side
//!   ([`service`]), the verifier thread ([`verifier`], [`exec`]) and each
//!   request on it ([`request`]), what it serves ([`served`]), its store
//!   ([`store`]) and its budgets ([`shared`]).

pub mod exec;
pub mod request;
pub mod served;
pub mod service;
pub mod shared;
pub mod store;
pub mod verifier;

/// The Colibri release the C core is built from.
pub const COLIBRI_VERSION: &str = "3.0.3";

/// The version number of [`COLIBRI_VERSION`] (`major << 16 | minor << 8 |
/// patch`), which the C core sends to provers and main pins (0014, "The
/// protocol").
pub const CLIENT_VERSION: u32 = 196_611;

/// The version number the linked C core reports.
pub fn client_version() -> u32 {
    colibri_stateless::get_current_version_number()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_linked_core_is_the_pinned_version() {
        assert_eq!(client_version(), CLIENT_VERSION);
        assert_eq!(CLIENT_VERSION, 3 << 16 | 3);
    }
}
