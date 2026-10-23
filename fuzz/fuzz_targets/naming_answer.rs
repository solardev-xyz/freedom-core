//! fc-naming's reading of what resolvers and gateways answer (design
//! 0006): a contenthash record, a CCIP-Read gateway's response, and ABI
//! data in each shape the resolution reads. All of it comes from the
//! network.
//!
//! The first byte picks the reader; the rest is its input. It checks,
//! besides panics, that a contenthash it reads gives a URI, and the ABI
//! decoder's output bound against an unbounded decode of the same data.
//! For ABI data, the two bytes after the first are the bound (big-endian,
//! so small inputs reach it):
//! - data whose unbounded decode returns more bytes and strings than the
//!   bound is refused;
//! - a decode within the bound returns what the unbounded one does;
//! - data whose unbounded decode returns no more than the bound decodes
//!   within it, unless a `string[]` field failed: its strings read before
//!   the failure count against the bound, as the reference counts what it
//!   produced (deviation `decode-budget`), but aren't in the answer.

#![no_main]

use fc_naming::abi::{self, Field, Kind, Value};
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

/// The bytes and strings `fields` hold: what the decode's output bound
/// counts, measured on what it returned.
fn footprint(fields: &[Field]) -> usize {
    fields
        .iter()
        .map(|field| match field {
            Ok(Value::Bytes(bytes)) => bytes.len(),
            Ok(Value::String(text)) => text.len(),
            Ok(Value::StringArray(items)) => items.iter().flatten().map(String::len).sum(),
            _ => 0,
        })
        .sum()
}

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
            let Some((limit, rest)) = rest.split_first_chunk::<2>() else {
                return;
            };
            let limit = usize::from(u16::from_be_bytes(*limit));
            let bounded = abi::decode_within(kinds, rest, limit);
            // The output bound is the only difference from an unbounded
            // decode (the read budget is the data's, either way).
            let Ok(fields) = abi::decode_within(kinds, rest, usize::MAX) else {
                assert!(bounded.is_err());
                return;
            };
            assert_eq!(fields.len(), kinds.len());
            if footprint(&fields) > limit {
                assert!(bounded.is_err());
                return;
            }
            let uncounted = kinds
                .iter()
                .zip(&fields)
                .any(|(&kind, field)| kind == Kind::StringArray && field.is_err());
            match bounded {
                Ok(within) => assert_eq!(within, fields),
                Err(_) => assert!(uncounted),
            }
        }
    }
});
