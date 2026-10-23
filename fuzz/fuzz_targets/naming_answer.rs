//! fc-naming's reading of what resolvers and gateways answer (design
//! 0006): a contenthash record, a CCIP-Read gateway's response, and ABI
//! data in each shape the resolution reads. All of it comes from the
//! network.
//!
//! The first byte picks the reader; the rest is its input. It checks,
//! besides panics, that a contenthash it reads gives a URI, and that ABI
//! data it decodes into one field per kind stays within the output bound.

#![no_main]

use fc_naming::abi::{self, Kind};
use fc_naming::ccip::parse_gateway_response;
use fc_naming::{cid_v1_bytes_to_base32, parse_contenthash};
use libfuzzer_sys::fuzz_target;

/// The shapes resolution decodes: `contenthash`/`text`/`addr` results,
/// and an `OffchainLookup` revert.
const SHAPES: [&[Kind]; 6] = [
    &[Kind::Bytes],
    &[Kind::String],
    &[Kind::Address],
    &[Kind::Uint256],
    &[Kind::StringArray],
    &[
        Kind::Address,
        Kind::StringArray,
        Kind::Bytes,
        Kind::Bytes4,
        Kind::Bytes,
    ],
];

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => {
            if let Some(content) = parse_contenthash(rest) {
                let _ = content.uri();
            }
        }
        1 => {
            let _ = cid_v1_bytes_to_base32(rest);
        }
        2 => {
            let _ = parse_gateway_response(rest);
        }
        _ => {
            let kinds = SHAPES[usize::from(mode / 4) % SHAPES.len()];
            if let Ok(fields) = abi::decode_within(kinds, rest, 1 << 16) {
                assert_eq!(fields.len(), kinds.len());
            }
        }
    }
});
