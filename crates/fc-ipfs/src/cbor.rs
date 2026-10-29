//! A bounded DAG-CBOR reader (0009, Bounded decoding): definite lengths
//! only, each checked against the bytes remaining; nesting at most
//! [`MAX_DEPTH`] levels (the outermost container the first), walked on an
//! explicit stack; map keys strings at every level, without duplicates in
//! the top-level map; tag 42 the only tag, wherever DAG-CBOR allows a link,
//! its content a CID (a byte string of 0x00 and a CID that parses). It
//! allocates nothing but its fixed stack.

/// The deepest nesting read; past it, structure is unverifiable
/// (deviation `decoder-caps`).
pub const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not DAG-CBOR the reader takes: an indefinite length, a length past
    /// the bytes, a key that isn't a string or repeats, another tag, or a
    /// tag 42 whose content isn't a CID.
    Malformed,
    /// Nested past [`MAX_DEPTH`].
    TooDeep,
}

/// A value of the top-level map the callers read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item<'a> {
    Uint(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    /// Anything else, skipped and checked.
    Other,
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let v = *self.b.get(self.at).ok_or(Error::Malformed)?;
        self.at += 1;
        Ok(v)
    }

    /// A head: major type and argument. Indefinite lengths and the reserved
    /// additional values are refused.
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let first = self.byte()?;
        let major = first >> 5;
        let ai = first & 0x1f;
        let arg = match ai {
            0..=23 => u64::from(ai),
            24..=27 => {
                let n = 1usize << (ai - 24);
                let bytes = self.take(n)?;
                bytes.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
            }
            _ => return Err(Error::Malformed),
        };
        // Major 7: only false, true, null and 64-bit floats.
        if major == 7 && !matches!(ai, 20..=22 | 27) {
            return Err(Error::Malformed);
        }
        Ok((major, arg))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Malformed)?;
        let s = self.b.get(self.at..end).ok_or(Error::Malformed)?;
        self.at = end;
        Ok(s)
    }

    fn take_len(&mut self, len: u64) -> Result<&'a [u8], Error> {
        self.take(usize::try_from(len).map_err(|_| Error::Malformed)?)
    }

    /// Skips one value whose head was read, at nesting `depth` (the
    /// container holding it is at `depth`), without recursion.
    fn skip(&mut self, major: u8, arg: u64, depth: usize) -> Result<(), Error> {
        // Items still to read in each open container, and whether it is a
        // map (whose items alternate key, value).
        let mut stack = [0u64; MAX_DEPTH + 1];
        let mut maps = [false; MAX_DEPTH + 1];
        let mut top = 0usize;
        let mut pending = Some((major, arg));
        loop {
            let (major, arg) = match pending.take() {
                Some(h) => h,
                None => {
                    while top > 0 && stack[top - 1] == 0 {
                        top -= 1;
                    }
                    if top == 0 {
                        return Ok(());
                    }
                    let key = maps[top - 1] && stack[top - 1] % 2 == 0;
                    stack[top - 1] -= 1;
                    let head = self.head()?;
                    if key && head.0 != 3 {
                        return Err(Error::Malformed);
                    }
                    head
                }
            };
            match major {
                0 | 1 => {}
                2 => {
                    self.take_len(arg)?;
                }
                3 => {
                    std::str::from_utf8(self.take_len(arg)?).map_err(|_| Error::Malformed)?;
                }
                4 | 5 => {
                    if depth + top + 1 > MAX_DEPTH {
                        return Err(Error::TooDeep);
                    }
                    let items = if major == 5 {
                        arg.checked_mul(2).ok_or(Error::Malformed)?
                    } else {
                        arg
                    };
                    // Each item needs at least a byte: a count past the
                    // bytes left can't be met.
                    if items > (self.b.len() - self.at) as u64 {
                        return Err(Error::Malformed);
                    }
                    stack[top] = items;
                    maps[top] = major == 5;
                    top += 1;
                }
                6 => {
                    if arg != 42 {
                        return Err(Error::Malformed);
                    }
                    let (m, a) = self.head()?;
                    if m != 2 {
                        return Err(Error::Malformed);
                    }
                    let cid = self.take_len(a)?;
                    match cid.split_first() {
                        Some((0, rest)) if crate::cid::parse(rest).is_some() => {}
                        _ => return Err(Error::Malformed),
                    }
                }
                // Major 7, already checked in `head`.
                _ => {}
            }
        }
    }
}

/// Reads `bytes` as one top-level map and every value in it (each checked
/// whole), and returns its entries in order. Trailing bytes are refused.
pub fn top_map(bytes: &[u8]) -> Result<Vec<(&str, Item<'_>)>, Error> {
    let mut r = Reader { b: bytes, at: 0 };
    let (major, count) = r.head()?;
    if major != 5 {
        return Err(Error::Malformed);
    }
    if count > bytes.len() as u64 {
        return Err(Error::Malformed);
    }
    let mut out: Vec<(&str, Item<'_>)> = Vec::new();
    for _ in 0..count {
        let (m, len) = r.head()?;
        if m != 3 {
            return Err(Error::Malformed);
        }
        let key = std::str::from_utf8(r.take_len(len)?).map_err(|_| Error::Malformed)?;
        if out.iter().any(|(k, _)| *k == key) {
            return Err(Error::Malformed);
        }
        let (m, arg) = r.head()?;
        let item = match m {
            0 => Item::Uint(arg),
            2 => Item::Bytes(r.take_len(arg)?),
            3 => Item::Text(std::str::from_utf8(r.take_len(arg)?).map_err(|_| Error::Malformed)?),
            _ => {
                r.skip(m, arg, 1)?;
                Item::Other
            }
        };
        out.push((key, item));
    }
    if r.at != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested(depth: usize) -> Vec<u8> {
        // {"aaa": {"a": {"a": … {}}}, "version": 1}, the outer map level 1.
        let mut v = vec![0xa2, 0x63, b'a', b'a', b'a'];
        for _ in 0..depth.saturating_sub(2) {
            v.extend_from_slice(&[0xa1, 0x61, b'a']);
        }
        v.push(0xa0);
        v.extend_from_slice(&[0x67, b'v', b'e', b'r', b's', b'i', b'o', b'n', 0x01]);
        v
    }

    #[test]
    fn depth_bound() {
        assert!(top_map(&nested(8)).is_ok());
        assert_eq!(top_map(&nested(9)), Err(Error::TooDeep));
    }

    #[test]
    fn refusals() {
        // An indefinite-length map; a length past the end; a repeated key;
        // a non-string key; tag 1; trailing bytes.
        for bad in [
            &[0xbf, 0xff][..],
            &[0xa1, 0x61, b'a', 0x59, 0xff, 0xff],
            &[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
            &[0xa1, 0x01, 0x01],
            &[0xa1, 0x61, b'a', 0xc1, 0x01],
            &[0xa0, 0x00],
            // A non-string key in a nested map; tag 42 over an integer,
            // over bytes without the 0x00 prefix, and over 0x00 and bytes
            // that aren't a CID.
            &[0xa1, 0x61, b'a', 0xa1, 0x01, 0x01],
            &[0xa1, 0x61, b'a', 0xd8, 0x2a, 0x01],
            &[0xa1, 0x61, b'a', 0xd8, 0x2a, 0x41, 0x01],
            &[0xa1, 0x61, b'a', 0xd8, 0x2a, 0x44, 0x00, 0x07, 0x07, 0x07],
        ] {
            assert_eq!(top_map(bad), Err(Error::Malformed), "{bad:02x?}");
        }
    }

    #[test]
    fn values() {
        let m = top_map(&[
            0xa3, 0x61, b'a', 0x18, 0x2a, 0x61, b'b', 0x42, 1, 2, 0x61, b'c', 0xf5,
        ])
        .unwrap_or_default();
        assert_eq!(
            m,
            vec![
                ("a", Item::Uint(42)),
                ("b", Item::Bytes(&[1, 2])),
                ("c", Item::Other)
            ]
        );
        // A link where DAG-CBOR allows one: 0x00, then a CID (CIDv1, raw,
        // an empty identity digest), here inside a nested map.
        let m = top_map(&[
            0xa1, 0x61, b'l', 0xa1, 0x61, b'x', 0xd8, 0x2a, 0x45, 0x00, 0x01, 0x55, 0x00, 0x00,
        ]);
        assert_eq!(m, Ok(vec![("l", Item::Other)]));
    }
}
