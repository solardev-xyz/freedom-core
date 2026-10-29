//! CID and IPNS-key canonicalization, as freedom-browser's
//! `shared/cid-utils.js` does it: CIDv0 and base58 CIDv1 to base32, and
//! base58 IPNS multihashes to libp2p-key base36. Both targets are lowercase,
//! so they survive Chromium lowercasing a standard-scheme host.

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const BASE36: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

fn base58_digit(byte: u8) -> Option<u64> {
    BASE58
        .iter()
        .position(|&c| c == byte)
        .and_then(|d| u64::try_from(d).ok())
}

/// A character of the base58 alphabet: `[1-9A-HJ-NP-Za-km-z]`.
pub(crate) fn is_base58(byte: u8) -> bool {
    base58_digit(byte).is_some()
}

/// `base58Decode`: leading `1`s are zero bytes; `None` for an empty string
/// or a character outside the alphabet.
///
/// Ten digits at a time into 64-bit limbs, so a 64 KiB host (the request
/// bound) decodes in milliseconds rather than the seconds a byte-at-a-time
/// big number takes.
pub(crate) fn base58_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return None;
    }
    decode_big(text, base58_digit, 58, 10, b'1')
}

/// A big number's digits in `base` to its big-endian bytes, with a zero
/// byte per leading `zero` digit; `None` for an empty string or a digit
/// `digit` refuses. `group` digits at a time go into 64-bit limbs
/// (`base^group` must fit), so a long text decodes in milliseconds.
fn decode_big(
    text: &str,
    digit: impl Fn(u8) -> Option<u64>,
    base: u64,
    group: usize,
    zero: u8,
) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    // Little-endian base-2^64 limbs.
    let mut limbs: Vec<u64> = Vec::new();
    for chunk in bytes.chunks(group) {
        let mut multiplier: u64 = 1;
        let mut addend: u64 = 0;
        for &byte in chunk {
            addend = addend * base + digit(byte)?;
            multiplier *= base;
        }
        let mut carry = u128::from(addend);
        for limb in &mut limbs {
            let product = u128::from(*limb) * u128::from(multiplier) + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry > 0 {
            limbs.push(carry as u64);
        }
    }
    let mut out: Vec<u8> = limbs
        .iter()
        .rev()
        .flat_map(|limb| limb.to_be_bytes())
        .collect();
    let significant = out.iter().position(|&b| b != 0).unwrap_or(out.len());
    out.drain(..significant);
    let leading = bytes.iter().take_while(|&&b| b == zero).count();
    let mut result = vec![0u8; leading];
    result.extend_from_slice(&out);
    Some(result)
}

/// Lowercase base36 (`0`–`9`, `a`–`z`), as the verify-plan generator's
/// `baseDecode` reads it: a `0` per leading zero byte; `None` for another
/// character. The empty string is no bytes.
pub(crate) fn base36_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let digit = |b: u8| {
        BASE36
            .iter()
            .position(|&c| c == b)
            .and_then(|d| u64::try_from(d).ok())
    };
    decode_big(text, digit, 36, 12, b'0')
}

/// Lowercase RFC 4648 base32 without padding, as the generator's
/// `base32Decode` reads it: leftover bits are dropped unchecked; `None`
/// for another character.
pub(crate) fn base32_decode_lenient(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut value: u32 = 0;
    let mut bits = 0u32;
    for b in text.bytes() {
        let v = BASE32.iter().position(|&c| c == b)? as u32;
        value = (value << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((value >> (bits - 8)) as u8);
            bits -= 8;
            value &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// RFC 4648 base32, lowercase, no padding.
pub(crate) fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = ((buffer & 0xff) << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            out.push(char::from(BASE32[((buffer >> (bits - 5)) & 0x1f) as usize]));
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 0x1f) as usize]));
    }
    out
}

/// Base36, lowercase: a big number's digits, with a `0` per leading zero
/// byte. Only used on multihashes of at most 129 bytes.
fn base36_encode(bytes: &[u8]) -> String {
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut number: Vec<u8> = bytes.get(leading_zeros..).unwrap_or_default().to_vec();
    let mut digits = Vec::new();
    while !number.is_empty() {
        let mut remainder: u32 = 0;
        let mut quotient = Vec::with_capacity(number.len());
        for &byte in &number {
            let value = remainder * 256 + u32::from(byte);
            let digit = value / 36;
            remainder = value % 36;
            if !(quotient.is_empty() && digit == 0) {
                quotient.push(digit as u8);
            }
        }
        digits.push(BASE36[remainder as usize]);
        number = quotient;
    }
    let mut out = "0".repeat(leading_zeros);
    out.extend(digits.iter().rev().map(|&d| char::from(d)));
    out
}

/// `readUvarint`: an unsigned LEB128 varint of at most five bytes, OR-ed
/// into a JavaScript int32 (`value |= (byte & 0x7f) << shift`), so bits past
/// 32 vanish and the fifth byte can turn it negative. `(value, length)`.
fn read_uvarint(bytes: &[u8], offset: usize) -> Option<(i32, usize)> {
    let mut value: i32 = 0;
    let mut shift: u32 = 0;
    let mut position = offset;
    while let Some(&byte) = bytes.get(position) {
        position += 1;
        value |= u32::from(byte & 0x7f).wrapping_shl(shift) as i32;
        if byte & 0x80 == 0 {
            return Some((value, position - offset));
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    None
}

/// Whether the bytes are a CIDv1: version 1, a codec, then a multihash
/// whose declared digest length accounts for every remaining byte.
fn is_cid_v1(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || bytes.first() != Some(&0x01) {
        return false;
    }
    let Some((_, codec)) = read_uvarint(bytes, 1) else {
        return false;
    };
    let Some((_, code)) = read_uvarint(bytes, 1 + codec) else {
        return false;
    };
    let Some((digest, length)) = read_uvarint(bytes, 1 + codec + code) else {
        return false;
    };
    let expected = (1 + codec + code + length) as i64 + i64::from(digest);
    i64::try_from(bytes.len()) == Ok(expected)
}

/// `/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/`.
fn is_cid_v0_shape(text: &str) -> bool {
    text.len() == 46 && text.starts_with("Qm") && text.bytes().skip(2).all(is_base58)
}

/// `cidV0ToV1Base32`: a CIDv0 (`Qm…`, a base58 sha2-256 multihash) to
/// CIDv1 dag-pb base32 (`bafy…`). `None` for anything else, including a
/// lowercased `qm…`, whose bytes are gone.
pub fn cid_v0_to_v1_base32(text: &str) -> Option<String> {
    if !is_cid_v0_shape(text) {
        return None;
    }
    let multihash = base58_decode(text)?;
    if multihash.len() != 34 || multihash.first() != Some(&0x12) || multihash.get(1) != Some(&0x20)
    {
        return None;
    }
    let mut v1 = vec![0x01, 0x70];
    v1.extend_from_slice(&multihash);
    Some(format!("b{}", base32_encode(&v1)))
}

/// `ipnsMhToCidV1Base36`: a base58 multihash (a peer ID: `12D3Koo…`,
/// `16Uiu2H…`, `Qm…`) to a CIDv1 libp2p-key in base36 (`k51…`). The code
/// and the digest length must each fit one varint byte.
pub fn ipns_mh_to_cid_v1_base36(text: &str) -> Option<String> {
    let multihash = base58_decode(text)?;
    let (&code, &length) = (multihash.first()?, multihash.get(1)?);
    if multihash.len() < 3 || code >= 0x80 || length >= 0x80 {
        return None;
    }
    if multihash.len() != 2 + usize::from(length) {
        return None;
    }
    let mut v1 = vec![0x01, 0x72];
    v1.extend_from_slice(&multihash);
    Some(format!("k{}", base36_encode(&v1)))
}

/// `cidV1B58btcToBase32`: a base58btc CIDv1 (`z…`) to base32 (`b…`).
/// `None` unless the text has the case-sensitive shape and at least one
/// uppercase letter (all-lowercase means a parser lowercased it, and the
/// bytes are gone), and decodes to a whole CIDv1.
pub fn cid_v1_b58btc_to_base32(text: &str) -> Option<String> {
    let body = text.strip_prefix('z')?;
    if body.len() < 40 || !body.bytes().all(is_base58) {
        return None;
    }
    if !text
        .bytes()
        .any(|b| b.is_ascii_uppercase() && b != b'I' && b != b'O')
    {
        return None;
    }
    let bytes = base58_decode(body)?;
    is_cid_v1(&bytes).then(|| format!("b{}", base32_encode(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_matches_a_byte_at_a_time_decode() {
        // 1..=40 digits, so every group size and carry is crossed.
        let digits = "3yZe7d4Pm2XQwEhsLtAuBkNf9oJVcRrGq6xKgWv5";
        for len in 1..=digits.len() {
            let text = &digits[..len];
            let mut slow = vec![0u8];
            for byte in text.bytes() {
                let mut carry = base58_digit(byte).unwrap() as u32;
                for b in slow.iter_mut().rev() {
                    let v = u32::from(*b) * 58 + carry;
                    *b = v as u8;
                    carry = v >> 8;
                }
                while carry > 0 {
                    slow.insert(0, carry as u8);
                    carry >>= 8;
                }
            }
            let significant = slow.iter().position(|&b| b != 0).unwrap_or(slow.len());
            assert_eq!(base58_decode(text).unwrap(), &slow[significant..], "{text}");
        }
        assert_eq!(base58_decode("111").unwrap(), [0, 0, 0]);
        assert_eq!(base58_decode("11z").unwrap(), [0, 0, 57]);
        assert_eq!(base58_decode(""), None);
        assert_eq!(base58_decode("0"), None);
    }

    #[test]
    fn varints_wrap_as_int32() {
        assert_eq!(
            read_uvarint(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0),
            Some((-1, 5))
        );
        assert_eq!(
            read_uvarint(&[0x80, 0x80, 0x80, 0x80, 0x10], 0),
            Some((0, 5))
        );
        assert_eq!(read_uvarint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00], 0), None);
        assert_eq!(read_uvarint(&[0xa9, 0x02], 0), Some((0x129, 2)));
    }
}
