//! A Ledger account's path: only the two schemes' forms (design 0016, "The
//! APDU grammar", deviation `path-strict`): `live`, `44'/60'/i'/0/0`, and
//! `legacy`, `44'/60'/0'/i`, with `i` from 0 to 2^31 − 1. hw-app-eth's
//! `splitPath` skips an element it can't read; the core refuses any other
//! text.

use std::fmt;

use fc_keys::{ChildIndex, DerivationPath};

/// The largest index a scheme's path takes: 2^31 − 1.
pub const MAX_INDEX: u32 = (1 << 31) - 1;

/// The two schemes `ledger:get-accounts` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `44'/60'/i'/0/0`.
    Live,
    /// `44'/60'/0'/i`.
    Legacy,
}

impl Scheme {
    /// `live` or `legacy`, as the request names it.
    pub fn parse(text: &str) -> Option<Scheme> {
        match text {
            "live" => Some(Scheme::Live),
            "legacy" => Some(Scheme::Legacy),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Live => "live",
            Scheme::Legacy => "legacy",
        }
    }
}

/// Why a path is refused before any APDU.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("not a scheme's path")]
    NotSchemePath,
    #[error("a path index above 2^31 - 1")]
    Index,
}

/// A path in one of the two schemes' forms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LedgerPath {
    scheme: Scheme,
    index: u32,
    path: DerivationPath,
}

impl LedgerPath {
    /// The scheme's path for `index`, which must be at most [`MAX_INDEX`].
    pub fn new(scheme: Scheme, index: u64) -> Result<Self, PathError> {
        let index = u32::try_from(index)
            .ok()
            .filter(|i| *i <= MAX_INDEX)
            .ok_or(PathError::Index)?;
        let hardened = |i: u32| ChildIndex::hardened(i).map_err(|_| PathError::Index);
        let normal = |i: u32| ChildIndex::normal(i).map_err(|_| PathError::Index);
        let children = match scheme {
            Scheme::Live => [
                hardened(44)?,
                hardened(60)?,
                hardened(index)?,
                normal(0)?,
                normal(0)?,
            ]
            .to_vec(),
            Scheme::Legacy => [hardened(44)?, hardened(60)?, hardened(0)?, normal(index)?].to_vec(),
        };
        Ok(LedgerPath {
            scheme,
            index,
            path: children.into_iter().collect(),
        })
    }

    /// A record's path text, exactly as a scheme writes it: no `m/`, no
    /// leading zeros, `'` for a hardened element. Any other text is
    /// refused.
    pub fn parse(text: &str) -> Result<Self, PathError> {
        let path: DerivationPath = format!("m/{text}")
            .parse()
            .map_err(|_| PathError::NotSchemePath)?;
        let element = |child: &ChildIndex, hardened: bool| {
            (child.is_hardened() == hardened).then_some(child.index())
        };
        let found = match path.children() {
            [a, b, c, d, e]
                if element(a, true) == Some(44)
                    && element(b, true) == Some(60)
                    && element(d, false) == Some(0)
                    && element(e, false) == Some(0) =>
            {
                element(c, true).map(|i| (Scheme::Live, i))
            }
            [a, b, c, d]
                if element(a, true) == Some(44)
                    && element(b, true) == Some(60)
                    && element(c, true) == Some(0) =>
            {
                element(d, false).map(|i| (Scheme::Legacy, i))
            }
            _ => None,
        };
        let (scheme, index) = found.ok_or(PathError::NotSchemePath)?;
        let parsed = LedgerPath::new(scheme, u64::from(index))?;
        // `44'/60'/01'/0/0` names the same key, but isn't the scheme's text.
        if parsed.to_string() != text {
            return Err(PathError::NotSchemePath);
        }
        Ok(parsed)
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn derivation_path(&self) -> &DerivationPath {
        &self.path
    }

    /// `P`: the number of elements, then each as 4 bytes, big-endian,
    /// `0x80000000` set for a hardened one.
    pub fn encode(&self) -> Vec<u8> {
        let children = self.path.children();
        let mut out = Vec::with_capacity(1 + 4 * children.len());
        // A scheme's path has 4 or 5 elements.
        out.push(children.len() as u8);
        for child in children {
            out.extend_from_slice(&child.to_be_bytes());
        }
        out
    }
}

impl fmt::Display for LedgerPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scheme {
            Scheme::Live => write!(f, "44'/60'/{}'/0/0", self.index),
            Scheme::Legacy => write!(f, "44'/60'/0'/{}", self.index),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_forms() {
        let live = LedgerPath::parse("44'/60'/7'/0/0").unwrap();
        assert_eq!((live.scheme(), live.index()), (Scheme::Live, 7));
        assert_eq!(
            live.encode(),
            [
                5, 0x80, 0, 0, 44, 0x80, 0, 0, 60, 0x80, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(live.derivation_path().to_string(), "m/44'/60'/7'/0/0");
        let legacy = LedgerPath::parse("44'/60'/0'/2147483647").unwrap();
        assert_eq!(
            (legacy.scheme(), legacy.index()),
            (Scheme::Legacy, MAX_INDEX)
        );
        assert_eq!(
            legacy.encode(),
            [
                4, 0x80, 0, 0, 44, 0x80, 0, 0, 60, 0x80, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff
            ]
        );
        assert_eq!(
            LedgerPath::parse("44'/60'/2147483647'/0/0")
                .unwrap()
                .index(),
            MAX_INDEX
        );
    }

    #[test]
    fn anything_else_is_refused() {
        for text in [
            "",
            "m/44'/60'/0'/0/0",
            "44'/60'/0'/0/1",
            "44'/60'/0'/1/0",
            "44'/60'/0/0/0",
            "44'/60'/0'/0'/0",
            "44'/60'/0'/0/0'",
            "44'/60'/1'/0",
            "44'/60'/0'/0'",
            "44'/61'/0'/0/0",
            "45'/60'/0'/0/0",
            "44'/60'/01'/0/0",
            "44'/60'/0'/00",
            "44'/60'/0'",
            "44'/60'/0'/0/0/0",
            "44'/60'/2147483648'/0/0",
            "44'/60'/0'/2147483648",
            "44'/60'/0'/0/0 ",
            "44h/60h/0h/0/0",
            "44'/60'/+1'/0/0",
        ] {
            assert!(LedgerPath::parse(text).is_err(), "{text:?}");
        }
        assert_eq!(
            LedgerPath::new(Scheme::Live, 1 << 31),
            Err(PathError::Index)
        );
    }

    #[test]
    fn text_round_trips() {
        for (scheme, index) in [
            (Scheme::Live, 0),
            (Scheme::Live, 19),
            (Scheme::Legacy, 0),
            (Scheme::Legacy, 1234),
        ] {
            let path = LedgerPath::new(scheme, index).unwrap();
            assert_eq!(LedgerPath::parse(&path.to_string()).unwrap(), path);
        }
    }
}
