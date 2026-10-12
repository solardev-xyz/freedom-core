//! Name resolution for Freedom (design 0003): ENSIP-15 normalization,
//! namehash and DNS encoding, contenthash decoding, with the behavior of freedom-browser's
//! `ens-resolver.js` and the ethers v6 it uses. `vectors/naming.json`,
//! produced by the pinned JS, is the contract.
//!
//! The crate does no I/O.

pub mod abi;
pub mod ccip;
mod contenthash;
mod ens;
mod error;
pub mod jsjson;
mod normalize;
pub mod session;
pub mod tezos;
pub mod ur;

/// Two ASCII hex digits as a byte. (`u8::from_str_radix` would also take a
/// sign, which no JavaScript check here allows.)
pub(crate) fn hex_byte(pair: &[u8]) -> Option<u8> {
    match pair {
        [hi, lo] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
            u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()
        }
        _ => None,
    }
}

pub use contenthash::{Content, cid_v1_bytes_to_base32, encode_base58, parse_contenthash};
pub use ens::{ETH_COIN_TYPE, coin_type, dns_encode, namehash};
pub use error::Error;
pub use normalize::{MAX_NAME_BYTES, js_trim, normalize_ens, normalize_tezos};
