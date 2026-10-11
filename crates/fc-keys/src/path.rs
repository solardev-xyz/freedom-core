//! BIP-32 derivation paths in the `m/44'/60'/0'/0/0` notation that
//! freedom-browser's registered paths use. Only `'` marks a hardened
//! segment, as in ethers.
//!
//! This is deliberately a subset, not a general parser. It rejects forms
//! that ethers or micro-key-producer also accept: relative paths without
//! `m/`, `M`, and `m'`. Freedom never builds those, and every path the core
//! derives comes from `freedom.rs`.

use std::fmt;
use std::str::FromStr;

use crate::Error;

const HARDENED_BIT: u32 = 1 << 31;

/// One path segment, stored as the BIP-32 `u32` (hardened bit included).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChildIndex(u32);

impl ChildIndex {
    /// A non-hardened index (`index < 2^31`).
    pub fn normal(index: u32) -> Result<Self, Error> {
        check(index)?;
        Ok(ChildIndex(index))
    }

    /// A hardened index (`index < 2^31`), written `index'`.
    pub fn hardened(index: u32) -> Result<Self, Error> {
        check(index)?;
        Ok(ChildIndex(index | HARDENED_BIT))
    }

    pub fn is_hardened(self) -> bool {
        self.0 & HARDENED_BIT != 0
    }

    /// The index without the hardened bit.
    pub fn index(self) -> u32 {
        self.0 & !HARDENED_BIT
    }

    /// `ser32(i)` from BIP-32: big-endian, hardened bit included.
    pub fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

fn check(index: u32) -> Result<(), Error> {
    if index >= HARDENED_BIT {
        return Err(Error::IndexOutOfRange(u64::from(index)));
    }
    Ok(())
}

/// A derivation path from the master key.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct DerivationPath(Vec<ChildIndex>);

impl DerivationPath {
    pub fn children(&self) -> &[ChildIndex] {
        &self.0
    }
}

impl FromIterator<ChildIndex> for DerivationPath {
    fn from_iter<I: IntoIterator<Item = ChildIndex>>(iter: I) -> Self {
        DerivationPath(iter.into_iter().collect())
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let mut segments = s.split('/');
        if segments.next() != Some("m") {
            return Err(Error::InvalidPath);
        }
        segments
            .map(|segment| {
                let (digits, hardened) = match segment.strip_suffix('\'') {
                    Some(digits) => (digits, true),
                    None => (segment, false),
                };
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::InvalidPath);
                }
                let index: u64 = digits.parse().map_err(|_| Error::InvalidPath)?;
                let index = u32::try_from(index)
                    .ok()
                    .filter(|i| *i < HARDENED_BIT)
                    .ok_or(Error::IndexOutOfRange(index))?;
                if hardened {
                    ChildIndex::hardened(index)
                } else {
                    ChildIndex::normal(index)
                }
            })
            .collect()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for child in &self.0 {
            write!(f, "/{}", child.index())?;
            if child.is_hardened() {
                f.write_str("'")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DerivationPath({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for path in [
            "m",
            "m/0",
            "m/44'/60'/0'/0/0",
            "m/0/2147483647'/1/2147483646'/2",
        ] {
            assert_eq!(path.parse::<DerivationPath>().unwrap().to_string(), path);
        }
    }

    #[test]
    fn rejects_malformed() {
        for path in [
            "", "M/0", "m/", "m//0", "m/0''", "m/-1", "m/0h", "m/ 1", "m/1/", "44'/60'",
        ] {
            assert_eq!(
                path.parse::<DerivationPath>().unwrap_err(),
                Error::InvalidPath,
                "{path:?}"
            );
        }
        assert_eq!(
            "m/2147483648'".parse::<DerivationPath>().unwrap_err(),
            Error::IndexOutOfRange(2_147_483_648)
        );
        assert_eq!(
            "m/99999999999".parse::<DerivationPath>().unwrap_err(),
            Error::IndexOutOfRange(99_999_999_999)
        );
    }
}
