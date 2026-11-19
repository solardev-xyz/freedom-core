//! Recursive-length prefix encoding and decoding, as Ethereum transactions
//! use it.
//!
//! [`decode`] is strict: every length in its shortest form (a single byte
//! below `0x80` is never wrapped), no bytes after the item, at most
//! [`MAX_DEPTH`] nested lists. [`Item::uint`] adds the integer rule: no
//! leading zeros, at most 256 bits. Decoding borrows from the input and
//! allocates nothing, so its cost is linear in the input whatever it holds.

use crate::U256;

fn header(out: &mut Vec<u8>, offset: u8, len: usize) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let len_bytes = (len as u64).to_be_bytes();
        let start = len_bytes.iter().position(|b| *b != 0).unwrap_or(7);
        out.push(offset + 55 + (8 - start) as u8);
        out.extend_from_slice(&len_bytes[start..]);
    }
}

/// A byte string.
pub fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    if value.len() == 1 && value[0] < 0x80 {
        out.push(value[0]);
    } else {
        header(out, 0x80, value.len());
        out.extend_from_slice(value);
    }
}

/// An integer: minimal big-endian bytes, empty for zero.
pub fn uint(out: &mut Vec<u8>, value: &U256) {
    bytes(out, &value.to_minimal_be());
}

/// A list of already-encoded items.
pub fn list(out: &mut Vec<u8>, payload: &[u8]) {
    header(out, 0xc0, payload.len());
    out.extend_from_slice(payload);
}

/// The most lists [`decode`] reads nested in one another.
pub const MAX_DEPTH: usize = 16;

/// Why bytes aren't one strict RLP item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RlpError {
    #[error("RLP: the input ends inside an item")]
    Truncated,
    #[error("RLP: bytes after the item")]
    Trailing,
    #[error("RLP: a length not in its shortest form")]
    NonCanonical,
    #[error("RLP: more than {MAX_DEPTH} nested lists")]
    TooDeep,
    #[error("RLP: a list where a byte string belongs")]
    ExpectedBytes,
    #[error("RLP: a byte string where a list belongs")]
    ExpectedList,
    #[error("RLP: an integer with a leading zero")]
    LeadingZero,
    #[error("RLP: an integer wider than 256 bits")]
    TooWide,
}

/// One item, borrowed from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item<'a> {
    Bytes(&'a [u8]),
    List(List<'a>),
}

/// A list's payload, read item by item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct List<'a> {
    payload: &'a [u8],
    strict: bool,
}

/// The items of a [`List`], in order.
#[derive(Debug, Clone)]
pub struct Items<'a> {
    rest: &'a [u8],
    strict: bool,
}

impl<'a> Item<'a> {
    /// The byte string, or [`RlpError::ExpectedBytes`] for a list.
    pub fn bytes(self) -> Result<&'a [u8], RlpError> {
        match self {
            Item::Bytes(bytes) => Ok(bytes),
            Item::List(_) => Err(RlpError::ExpectedBytes),
        }
    }

    /// The list, or [`RlpError::ExpectedList`] for a byte string.
    pub fn list(self) -> Result<List<'a>, RlpError> {
        match self {
            Item::List(list) => Ok(list),
            Item::Bytes(_) => Err(RlpError::ExpectedList),
        }
    }

    /// An integer: big-endian with no leading zero (zero is the empty
    /// string), at most 32 bytes.
    pub fn uint(self) -> Result<U256, RlpError> {
        let bytes = self.bytes()?;
        if bytes.first() == Some(&0) {
            return Err(RlpError::LeadingZero);
        }
        U256::from_be_slice(bytes).ok_or(RlpError::TooWide)
    }
}

impl<'a> List<'a> {
    /// The items, each read as strictly as the list was.
    pub fn items(&self) -> Items<'a> {
        Items {
            rest: self.payload,
            strict: self.strict,
        }
    }

    /// The encoded items, without the list's header.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl<'a> Iterator for Items<'a> {
    type Item = Result<Item<'a>, RlpError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        Some(match next(self.rest, self.strict) {
            Ok((item, rest)) => {
                self.rest = rest;
                Ok(item)
            }
            Err(error) => {
                self.rest = &[];
                Err(error)
            }
        })
    }
}

/// `input` as exactly one strict item: shortest lengths, no trailing bytes,
/// at most [`MAX_DEPTH`] nested lists. The whole tree is checked here, so
/// reading its items afterwards fails only as [`Item::uint`],
/// [`Item::bytes`] or [`Item::list`] does.
pub fn decode(input: &[u8]) -> Result<Item<'_>, RlpError> {
    let item = single(input, true)?;
    check_tree(item, 0)?;
    Ok(item)
}

/// `input` as exactly one item, read as ethers' `decodeRlp` reads it: a
/// length in a longer form than needed is accepted, and nothing below the
/// first item is read until asked for. The caller checks the shortest form
/// by encoding the value again ([`crate::decode_signed`]).
pub(crate) fn decode_lenient(input: &[u8]) -> Result<Item<'_>, RlpError> {
    single(input, false)
}

fn single(input: &[u8], strict: bool) -> Result<Item<'_>, RlpError> {
    let (item, rest) = next(input, strict)?;
    if !rest.is_empty() {
        return Err(RlpError::Trailing);
    }
    Ok(item)
}

/// Every list below `item`, `depth` lists down already.
fn check_tree(item: Item<'_>, depth: usize) -> Result<(), RlpError> {
    if let Item::List(list) = item {
        if depth >= MAX_DEPTH {
            return Err(RlpError::TooDeep);
        }
        for child in list.items() {
            check_tree(child?, depth + 1)?;
        }
    }
    Ok(())
}

/// The item at the start of `input`, and the bytes after it.
fn next(input: &[u8], strict: bool) -> Result<(Item<'_>, &[u8]), RlpError> {
    let Some((&first, rest)) = input.split_first() else {
        return Err(RlpError::Truncated);
    };
    match first {
        0x00..=0x7f => Ok((Item::Bytes(&input[..1]), rest)),
        0x80..=0xb7 => {
            let (payload, after) = split(rest, usize::from(first - 0x80))?;
            if strict && matches!(payload, [byte] if *byte < 0x80) {
                return Err(RlpError::NonCanonical);
            }
            Ok((Item::Bytes(payload), after))
        }
        0xb8..=0xbf => {
            let (len, rest) = long_length(rest, usize::from(first - 0xb7), strict)?;
            let (payload, after) = split(rest, len)?;
            Ok((Item::Bytes(payload), after))
        }
        0xc0..=0xf7 => {
            let (payload, after) = split(rest, usize::from(first - 0xc0))?;
            Ok((Item::List(List { payload, strict }), after))
        }
        0xf8..=0xff => {
            let (len, rest) = long_length(rest, usize::from(first - 0xf7), strict)?;
            let (payload, after) = split(rest, len)?;
            Ok((Item::List(List { payload, strict }), after))
        }
    }
}

/// A long form's length: `size` (1 to 8) big-endian bytes. Strictly, with
/// no leading zero and at least 56, below which the short form applies.
fn long_length(input: &[u8], size: usize, strict: bool) -> Result<(usize, &[u8]), RlpError> {
    let (bytes, rest) = split(input, size)?;
    if strict && bytes.first() == Some(&0) {
        return Err(RlpError::NonCanonical);
    }
    let len = bytes
        .iter()
        .fold(0u64, |len, byte| (len << 8) | u64::from(*byte));
    // Past the address space, it is past the input too.
    let len = usize::try_from(len).map_err(|_| RlpError::Truncated)?;
    if strict && len < 56 {
        return Err(RlpError::NonCanonical);
    }
    Ok((len, rest))
}

fn split(input: &[u8], len: usize) -> Result<(&[u8], &[u8]), RlpError> {
    if len > input.len() {
        return Err(RlpError::Truncated);
    }
    Ok(input.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut out = Vec::new();
        f(&mut out);
        out
    }

    #[test]
    fn known_encodings() {
        assert_eq!(enc(|o| bytes(o, b"")), [0x80]);
        assert_eq!(enc(|o| bytes(o, &[0x00])), [0x00]);
        assert_eq!(enc(|o| bytes(o, &[0x7f])), [0x7f]);
        assert_eq!(enc(|o| bytes(o, &[0x80])), [0x81, 0x80]);
        assert_eq!(enc(|o| bytes(o, b"dog")), [0x83, b'd', b'o', b'g']);
        let long = [0xaa; 56];
        assert_eq!(enc(|o| bytes(o, &long))[..2], [0xb8, 56]);
        let longer = vec![0xaa; 1024];
        assert_eq!(enc(|o| bytes(o, &longer))[..3], [0xb9, 0x04, 0x00]);
        assert_eq!(enc(|o| uint(o, &U256::ZERO)), [0x80]);
        assert_eq!(enc(|o| uint(o, &U256::from_u64(15))), [0x0f]);
        assert_eq!(enc(|o| uint(o, &U256::from_u64(1024))), [0x82, 0x04, 0x00]);
        assert_eq!(enc(|o| list(o, &[])), [0xc0]);
        let cat_dog = [0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
        assert_eq!(enc(|o| list(o, &cat_dog))[0], 0xc8);
    }

    fn items(item: Item<'_>) -> Vec<Item<'_>> {
        item.list()
            .unwrap()
            .items()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn decodes_what_it_encodes() {
        for value in [
            vec![],
            vec![0x00],
            vec![0x7f],
            vec![0x80],
            b"dog".to_vec(),
            vec![0xaa; 55],
            vec![0xaa; 56],
            vec![0xaa; 1024],
            vec![0xaa; 70_000],
        ] {
            let encoded = enc(|o| bytes(o, &value));
            assert_eq!(decode(&encoded), Ok(Item::Bytes(&value[..])));
        }
        for len in [0usize, 1, 55, 56, 300, 70_000] {
            let payload = vec![0x01; len];
            let encoded = enc(|o| list(o, &payload));
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded.list().unwrap().payload(), &payload[..]);
            assert_eq!(items(decoded).len(), len);
        }
        let mut nested = Vec::new();
        bytes(&mut nested, b"cat");
        list(&mut nested, &enc(|o| bytes(o, b"")));
        let encoded = enc(|o| list(o, &nested));
        let decoded = items(decode(&encoded).unwrap());
        assert_eq!(decoded[0], Item::Bytes(b"cat"));
        assert_eq!(items(decoded[1]), [Item::Bytes(b"")]);
    }

    #[test]
    fn lengths_must_be_in_their_shortest_form() {
        for input in [
            &[0x81, 0x00][..],
            &[0x81, 0x7f],
            &[0xb8, 0x00],
            &[0xb8, 0x01, 0x80],
            &[0xb8, 0x37],
            &[0xf8, 0x00],
            &[0xf8, 0x37],
            // A zero first length byte, even before a length that needs
            // the long form.
            &[0xb9, 0x00, 0x38],
            &[0xf9, 0x00, 0x38],
            // Inside a list too.
            &[0xc2, 0x81, 0x05],
        ] {
            assert_eq!(decode(input), Err(RlpError::NonCanonical), "{input:02x?}");
        }
        // The lenient reader takes all of them, as ethers does.
        assert_eq!(decode_lenient(&[0x81, 0x05]), Ok(Item::Bytes(&[0x05][..])));
        assert_eq!(decode_lenient(&[0xb8, 0x00]), Ok(Item::Bytes(&[][..])));
        let lenient = decode_lenient(&[0xf8, 0x02, 0x81, 0x05]).unwrap();
        assert_eq!(items(lenient), [Item::Bytes(&[0x05][..])]);
        // The single bytes that need wrapping still decode.
        assert_eq!(decode(&[0x81, 0x80]), Ok(Item::Bytes(&[0x80][..])));
        assert_eq!(decode(&[0x81, 0xff]), Ok(Item::Bytes(&[0xff][..])));
    }

    #[test]
    fn truncation_and_trailing_bytes() {
        for input in [
            &[][..],
            &[0x81],
            &[0x83, b'd', b'o'],
            &[0xb8],
            &[0xb9, 0x01],
            &[0xb8, 0x38],
            &[0xc1],
            &[0xf8, 0x38, 0x00],
            // A child that runs past its list.
            &[0xc2, 0x82, 0x00],
            // Lengths past any input: 2^64 - 1 and 2^56.
            &[0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ] {
            let lenient = decode_lenient(input).and_then(|item| match item {
                Item::List(list) => list.items().try_for_each(|item| item.map(drop)),
                Item::Bytes(_) => Ok(()),
            });
            assert_eq!(decode(input), Err(RlpError::Truncated), "{input:02x?}");
            assert!(lenient.is_err(), "{input:02x?}");
        }
        for input in [&[0x80, 0x00][..], &[0x05, 0x05], &[0xc0, 0xc0]] {
            assert_eq!(decode(input), Err(RlpError::Trailing), "{input:02x?}");
            assert_eq!(decode_lenient(input), Err(RlpError::Trailing));
        }
    }

    #[test]
    fn depth_is_bounded() {
        let nest = |depth: usize| {
            let mut out = vec![0x80];
            for _ in 0..depth {
                out = enc(|o| list(o, &out));
            }
            out
        };
        assert!(decode(&nest(MAX_DEPTH)).is_ok());
        assert_eq!(decode(&nest(MAX_DEPTH + 1)), Err(RlpError::TooDeep));
        // Deeper than any stack, refused without recursing past the bound.
        let mut deep = vec![0xc0];
        for _ in 0..100_000 {
            deep = enc(|o| list(o, &deep));
        }
        assert_eq!(decode(&deep), Err(RlpError::TooDeep));
        // A non-canonical length below the bound is still found.
        let mut bad = vec![0x81, 0x05];
        for _ in 0..3 {
            bad = enc(|o| list(o, &bad));
        }
        assert_eq!(decode(&bad), Err(RlpError::NonCanonical));
    }

    #[test]
    fn integers() {
        let uint = |input: &[u8]| decode(input).and_then(Item::uint);
        assert_eq!(uint(&[0x80]), Ok(U256::ZERO));
        assert_eq!(uint(&[0x0f]), Ok(U256::from_u64(15)));
        assert_eq!(uint(&[0x82, 0x04, 0x00]), Ok(U256::from_u64(1024)));
        assert_eq!(uint(&[0x00]), Err(RlpError::LeadingZero));
        assert_eq!(uint(&[0x82, 0x00, 0x01]), Err(RlpError::LeadingZero));
        let max = [&[0xa0][..], &[0xff; 32]].concat();
        assert_eq!(uint(&max), Ok(U256::MAX));
        let wide = [&[0xa1][..], &[0x01], &[0x00; 32]].concat();
        assert_eq!(uint(&wide), Err(RlpError::TooWide));
        assert_eq!(uint(&[0xc0]), Err(RlpError::ExpectedBytes));
        assert_eq!(
            decode(&[0x80]).and_then(Item::list),
            Err(RlpError::ExpectedList)
        );
        for value in [
            U256::ZERO,
            U256::from_u64(1),
            U256::from_u64(0x80),
            U256::MAX,
        ] {
            assert_eq!(uint(&enc(|o| uint_enc(o, &value))), Ok(value));
        }
    }

    fn uint_enc(out: &mut Vec<u8>, value: &U256) {
        uint(out, value);
    }
}
