//! A broadcast's transaction hash: keccak-256 of the signed bytes, compared
//! as 32-byte values whatever the hex case (design 0005, Broadcast).

use fc_json::index::{Index, Kind};
use sha3::{Digest as _, Keccak256};

/// A transaction hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxHash([u8; 32]);

/// The raw transaction is not hex bytes: `0x` (or `0X`) and an even number
/// of hex digits, as ethers' `keccak256` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the raw transaction is not 0x-prefixed hex bytes")]
pub struct NotHex;

/// The hash of a raw signed transaction given as hex.
pub fn transaction_hash(raw: &str) -> Result<TxHash, NotHex> {
    let bytes = hex_bytes(raw).ok_or(NotHex)?;
    Ok(TxHash(Keccak256::digest(&bytes).into()))
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    if digits.len() % 2 != 0 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

impl TxHash {
    /// A hash written as `0x` (or `0X`) and 64 hex digits, any case.
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = hex_bytes(text)?;
        Some(Self(bytes.try_into().ok()?))
    }

    /// A hash given as a JSON value's text: a string holding
    /// [`Self::from_hex`]'s form (escapes and all).
    pub fn from_json(text: &str) -> Option<Self> {
        let index = Index::new(text).ok()?;
        let root = index.root();
        if root.kind() != Kind::String {
            return None;
        }
        let units: Vec<u16> = root.units().collect();
        Self::from_hex(&String::from_utf16(&units).ok()?)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `0x` and 64 lowercase hex digits, as ethers writes it.
    pub fn to_hex(&self) -> String {
        let mut out = String::from("0x");
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl std::fmt::Debug for TxHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_compare_as_bytes() {
        let empty = transaction_hash("0x").unwrap();
        assert_eq!(
            empty.to_hex(),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            TxHash::from_hex(&empty.to_hex().to_uppercase().replacen("0X", "0x", 1)),
            Some(empty)
        );
        assert_eq!(
            TxHash::from_hex(&empty.to_hex().to_uppercase()),
            Some(empty)
        );
        assert_eq!(
            TxHash::from_json(&format!(
                "\"{}\"",
                empty.to_hex().replacen('c', "\\u0043", 1)
            )),
            Some(empty)
        );
        assert_eq!(TxHash::from_hex(&empty.to_hex()[..65]), None);
        assert_eq!(TxHash::from_hex(&empty.to_hex()[2..]), None);
        assert_eq!(TxHash::from_json("1"), None);
        assert_eq!(transaction_hash("0x0"), Err(NotHex));
        assert_eq!(transaction_hash("02"), Err(NotHex));
        assert_eq!(transaction_hash(" 0x02"), Err(NotHex));
    }
}
