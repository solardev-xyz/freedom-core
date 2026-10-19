use sha3::{Digest, Keccak256};

use crate::{Error, quoted};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// An address as ethers takes it when signing: `0x` and 40 hex digits; with
/// mixed-case letters, the EIP-55 checksum must match. (ethers' `getAddress`
/// also takes no prefix and ICAP, but signing then treats such a value as an
/// ENS name and fails without a provider.)
pub fn parse_address(text: &str) -> Result<[u8; 20], Error> {
    let digits = text
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 40 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Value(format!("address {}", quoted(text))))?;
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16)
            .map_err(|_| Error::Value(format!("address {}", quoted(text))))?;
    }
    let has_upper = digits.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = digits.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower && checksum_address(&out)[2..] != *digits {
        return Err(Error::Value(format!("address checksum {}", quoted(text))));
    }
    Ok(out)
}

/// The address of a signing key: the last 20 bytes of the keccak256 of its
/// uncompressed public key.
pub fn address_of(key: &k256::ecdsa::SigningKey) -> [u8; 20] {
    use k256::elliptic_curve::sec1::ToSec1Point;
    let point = key.verifying_key().as_affine().to_sec1_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// EIP-55 checksummed `0x` form.
pub fn checksum_address(address: &[u8; 20]) -> String {
    let lower = crate::to_hex(address);
    let hash = keccak256(&lower.as_bytes()[2..]);
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower[2..].chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
        out.push(if nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55() {
        let checksummed = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";
        let address = parse_address(checksummed).unwrap();
        assert_eq!(checksum_address(&address), checksummed);
        assert_eq!(parse_address(&checksummed.to_lowercase()).unwrap(), address);
        let upper = format!("0x{}", checksummed[2..].to_uppercase());
        assert_eq!(parse_address(&upper).unwrap(), address);
        for bad in [
            "0x8Ba1f109551bD432803012645Ac136ddd64DBA72",
            "8ba1f109551bd432803012645ac136ddd64dba72",
            "0X8ba1f109551bd432803012645ac136ddd64dba72",
            "0x8ba1f109551bd432803012645ac136ddd64dba7",
            "0x8ba1f109551bd432803012645ac136ddd64dba7g",
        ] {
            assert!(parse_address(bad).is_err(), "{bad}");
        }
    }
}
