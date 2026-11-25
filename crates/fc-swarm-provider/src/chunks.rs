//! Chunks as the reference reads them: bee-js 13.2.0's
//! `unmarshalContentAddressedChunk` and `unmarshalSingleOwnerChunk` (its
//! `@ethersphere/core-sdk` 0.2.2, over `@noble/curves`), with the texts of
//! what they throw where a page reads them; chunk-service.js's
//! `dataSizeFromSpan` and `spanToResult`; and core-sdk's `Bytes` from hex.
//!
//! The hashing is fc-swarm's (the BMT, the SOC address); the rules are the
//! reference's, where they differ from 0009's (fc-swarm's `verify`, Ant's):
//! - a content-addressed chunk's payload is 1 to 4,096 bytes: core-sdk's
//!   `makeContentAddressedChunk` refuses the empty one, which 0009 reads
//!   as an empty file;
//! - a single-owner chunk's signature recovers as noble does it: `v` 27 is
//!   recovery 0 and any other `v` recovery 1, a high `s` recovers, and
//!   the replicas owner is an owner like any other. fc-evm's
//!   `recover_address` (0009's) takes only `v` 27 or 28 and a low `s`.

use fc_evm::{eip191_digest, keccak256};
use fc_swarm::CHUNK_SIZE;
use fc_swarm::verify::{SPAN_SIZE, address_of, bmt_root_of, soc_address};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

use crate::value::Value;

/// A content-addressed chunk the reference took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cac<'a> {
    /// The span as sent, its top byte included.
    pub span: [u8; SPAN_SIZE],
    pub payload: &'a [u8],
}

/// `unmarshalContentAddressedChunk(wire)` and `ensureSameReference` with
/// `address`: a span and a payload of 1 to 4,096 bytes whose address is
/// `address`. Every refusal reads the same to a page
/// (`chunk_type_mismatch`).
pub fn content_addressed<'a>(address: &[u8; 32], wire: &'a [u8]) -> Option<Cac<'a>> {
    let span: [u8; SPAN_SIZE] = wire.get(..SPAN_SIZE)?.try_into().ok()?;
    let payload = &wire[SPAN_SIZE..];
    if payload.is_empty() || payload.len() > CHUNK_SIZE {
        return None;
    }
    (address_of(&span, payload)? == *address).then_some(Cac { span, payload })
}

/// A single-owner chunk the reference took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Soc<'a> {
    pub identifier: [u8; 32],
    pub signature: [u8; 65],
    pub owner: [u8; 20],
    pub span: [u8; SPAN_SIZE],
    pub payload: &'a [u8],
}

impl Soc<'_> {
    /// The address of the chunk it wraps.
    pub fn wrapped_address(&self) -> Option<[u8; 32]> {
        address_of(&self.span, self.payload)
    }
}

const ID: usize = 32;
const SIGNATURE: usize = 65;
const HEADER: usize = ID + SIGNATURE;

/// The group's order, big-endian.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// core-sdk's `unmarshalSingleOwnerChunk(wire, address)`, with the message
/// of what it throws, in its order:
/// 1. fewer than 32 bytes: the identifier's length;
/// 2. a payload past 4,096 bytes (`calculateBmtRootHash`);
/// 3. fewer than 97 bytes: `BigInt(undefined)` reading the signature;
/// 4. `r` or `s` outside 1..n−1, a point not on the curve, the point at
///    infinity (noble's recovery);
/// 5. an owner whose SOC address isn't `address`;
/// 6. a span of fewer than 8 bytes.
pub fn single_owner<'a>(address: &[u8; 32], wire: &'a [u8]) -> Result<Soc<'a>, String> {
    if wire.len() < ID {
        return Err(byte_length(wire.len(), "32"));
    }
    let body = wire.get(HEADER..).unwrap_or(&[]);
    let (span_part, payload) = body.split_at(body.len().min(SPAN_SIZE));
    if payload.len() > CHUNK_SIZE {
        return Err(format!(
            "payload size {} exceeds maximum chunk payload size {CHUNK_SIZE}",
            payload.len()
        ));
    }
    // calculateChunkAddress over what is there: a short span is hashed as
    // it is.
    let root = bmt_root_of(payload).ok_or_else(|| String::from("payload size"))?;
    let mut cac_input = Vec::with_capacity(span_part.len() + 32);
    cac_input.extend_from_slice(span_part);
    cac_input.extend_from_slice(&root);
    let cac_address = keccak256(&cac_input);
    if wire.len() < HEADER {
        return Err(String::from("Cannot convert undefined to a BigInt"));
    }
    let mut identifier = [0u8; ID];
    identifier.copy_from_slice(&wire[..ID]);
    let mut signature = [0u8; SIGNATURE];
    signature.copy_from_slice(&wire[ID..HEADER]);
    let mut signed = [0u8; 64];
    signed[..32].copy_from_slice(&identifier);
    signed[32..].copy_from_slice(&cac_address);
    let digest = eip191_digest(&keccak256(&signed));
    let owner = recover_owner(&digest, &signature)?;
    if soc_address(&identifier, &owner) != *address {
        return Err(String::from("SOC data does not match given address"));
    }
    let span: [u8; SPAN_SIZE] = span_part
        .try_into()
        .map_err(|_| byte_length(span_part.len(), "8"))?;
    Ok(Soc {
        identifier,
        signature,
        owner,
        span,
        payload,
    })
}

/// noble's `new Signature(r, s, recovery).recoverPublicKey(digest)` as
/// core-sdk's `recoverPublicKey` calls it, then the owner's address.
fn recover_owner(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20], String> {
    let r_bytes: [u8; 32] = signature[..32].try_into().unwrap_or([0; 32]);
    let s_bytes: [u8; 32] = signature[32..64].try_into().unwrap_or([0; 32]);
    let in_range = |b: &[u8; 32]| b.iter().any(|&x| x != 0) && *b < ORDER;
    if !in_range(&r_bytes) {
        return Err(String::from(
            "invalid signature r: out of range 1..Point.Fn.ORDER",
        ));
    }
    if !in_range(&s_bytes) {
        return Err(String::from(
            "invalid signature s: out of range 1..Point.Fn.ORDER",
        ));
    }
    let recovery = if signature[64] == 27 { 0u8 } else { 1u8 };
    let r_field = FieldBytes::from(r_bytes);
    let point: Option<AffinePoint> =
        AffinePoint::decompress(&r_field, Choice::from(recovery)).into();
    let point = point.ok_or_else(|| {
        String::from("bad point: is not on curve, sqrt error: Cannot find square root")
    })?;
    let r: Option<Scalar> = Scalar::from_repr(r_field).into();
    let s: Option<Scalar> = Scalar::from_repr(FieldBytes::from(s_bytes)).into();
    let (Some(r), Some(s)) = (r, s) else {
        return Err(String::from(
            "invalid signature r: out of range 1..Point.Fn.ORDER",
        ));
    };
    let r_inv: Option<Scalar> = r.invert().into();
    let r_inv =
        r_inv.ok_or_else(|| String::from("invalid signature r: out of range 1..Point.Fn.ORDER"))?;
    let h = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*digest));
    let u1 = -(h * r_inv);
    let u2 = s * r_inv;
    let q = ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(point) * u2;
    if q == ProjectivePoint::IDENTITY {
        return Err(String::from("point at infinify"));
    }
    let encoded = q.to_affine().to_sec1_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&hash[12..]);
    Ok(owner)
}

fn byte_length(length: usize, expected: &str) -> String {
    format!("Bytes#checkByteLength: bytes length is {length} but expected {expected}")
}

/// chunk-service.js's `dataSizeFromSpan`: a top byte past 128 is a
/// redundancy level and is cleared; any other value is the size.
pub fn data_size(span: &[u8; SPAN_SIZE]) -> u64 {
    let mut bytes = *span;
    if bytes[SPAN_SIZE - 1] > 128 {
        bytes[SPAN_SIZE - 1] = 0;
    }
    u64::from_le_bytes(bytes)
}

/// The span's value, little-endian, its top byte included (`Span.toBigInt`).
pub fn span_value(span: &[u8; SPAN_SIZE]) -> u64 {
    u64::from_le_bytes(*span)
}

/// The largest integer a double holds exactly (`Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// `n <= Number.MAX_SAFE_INTEGER ? Number(n) : n`: chunk-service.js's
/// `spanToResult`, and the `actual` of a size past the read budget.
pub fn safe_number(n: u64) -> Value {
    if n <= MAX_SAFE_INTEGER {
        Value::int(n)
    } else {
        Value::BigInt(n.to_string())
    }
}

/// Lowercase hex, as bee-js's `toHex` writes it (no `0x`).
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

/// Hex digits to bytes, for text already checked to be hex of even length.
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let digit = |c: u8| char::from(c).to_digit(16);
    let mut out = [0u8; N];
    for (i, pair) in bytes.chunks(2).enumerate() {
        out[i] = u8::try_from(digit(pair[0])? * 16 + digit(pair[1])?).ok()?;
    }
    Some(out)
}

/// core-sdk's `new Bytes(text, length)` for a string (`EthAddress`,
/// `FeedIndex`): `Err` with its message.
pub fn bytes_from_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.is_empty() {
        return Err(String::from(
            "Bytes#constructor: constructor parameter is falsy: ",
        ));
    }
    let digits = match text.get(..2) {
        Some("0x" | "0X") => &text[2..],
        _ => text,
    };
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) || !digits.len().is_multiple_of(2) {
        return Err(format!("Bytes#constructor: invalid hex string: {text}"));
    }
    if digits.len() / 2 != N {
        return Err(byte_length(digits.len() / 2, &N.to_string()));
    }
    unhex::<N>(digits).ok_or_else(|| format!("Bytes#constructor: invalid hex string: {text}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn data_size_clears_a_level_byte_only() {
        let mut span = 8192u64.to_le_bytes();
        span[7] = 0x81;
        assert_eq!(data_size(&span), 8192);
        span[7] = 0x80;
        assert_eq!(data_size(&span), 8192 + (0x80u64 << 56));
    }

    #[test]
    fn bytes_from_hex_as_core_sdk() {
        assert_eq!(
            bytes_from_hex::<8>("zz").unwrap_err(),
            "Bytes#constructor: invalid hex string: zz"
        );
        assert_eq!(
            bytes_from_hex::<8>("7").unwrap_err(),
            "Bytes#constructor: invalid hex string: 7"
        );
        assert_eq!(
            bytes_from_hex::<8>("00").unwrap_err(),
            "Bytes#checkByteLength: bytes length is 1 but expected 8"
        );
        assert_eq!(
            bytes_from_hex::<8>("").unwrap_err(),
            "Bytes#constructor: constructor parameter is falsy: "
        );
        assert_eq!(bytes_from_hex::<8>("0X0000000000000007").unwrap()[7], 7);
    }

    #[test]
    fn a_short_soc_fails_on_its_identifier() {
        assert_eq!(
            single_owner(&[0; 32], b"\x05\0\0\0\0\0\0\0hello").unwrap_err(),
            "Bytes#checkByteLength: bytes length is 13 but expected 32"
        );
        assert_eq!(
            single_owner(&[0; 32], &[1; 50]).unwrap_err(),
            "Cannot convert undefined to a BigInt"
        );
        let mut zero_r = vec![0u8; 120];
        zero_r[96] = 27;
        assert_eq!(
            single_owner(&[0; 32], &zero_r).unwrap_err(),
            "invalid signature r: out of range 1..Point.Fn.ORDER"
        );
    }

    #[test]
    fn the_empty_payload_is_no_cac() {
        let address = address_of(&[0; 8], &[]).unwrap();
        assert!(content_addressed(&address, &[0; 8]).is_none());
        let address = address_of(&[1, 0, 0, 0, 0, 0, 0, 0], &[7]).unwrap();
        assert!(content_addressed(&address, &[1, 0, 0, 0, 0, 0, 0, 0, 7]).is_some());
    }
}
