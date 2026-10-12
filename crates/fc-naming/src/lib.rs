//! Name resolution for Freedom (design 0003): ENSIP-15 normalization,
//! namehash and DNS encoding, with the behavior of freedom-browser's
//! `ens-resolver.js` and the ethers v6 it uses. `vectors/naming.json`,
//! produced by the pinned JS, is the contract.
//!
//! The crate does no I/O.

mod ens;
mod error;
mod normalize;

pub use ens::{ETH_COIN_TYPE, coin_type, dns_encode, namehash};
pub use error::Error;
pub use normalize::{MAX_NAME_BYTES, js_trim, normalize_ens, normalize_tezos};
