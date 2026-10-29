//! A bounded DAG-CBOR reader (0009, Bounded decoding), in DAG-CBOR's
//! strict profile at every level: definite lengths only, each checked
//! against the bytes remaining; integers, lengths and counts in their
//! shortest form; map keys strings in canonical order (shorter first,
//! then bytewise), so none repeats; 64-bit floats that are finite and not
//! negative zero, and
//! `false`, `true` and `null` the only simple values; tag 42 the only
//! tag, wherever DAG-CBOR allows a link, its content 0x00 and one whole
//! CID (its varints minimal). Nesting is at most [`MAX_DEPTH`] levels, the
//! outermost container the first, walked on a fixed stack.
//!
//! [`top_map`] validates all of it without allocating; [`Map::get`] then
//! reads a top-level value by its key, again without allocating.

use crate::cid;

/// The deepest nesting read; past it, structure is unverifiable
/// (deviation `decoder-caps`).
pub const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not DAG-CBOR the reader takes: an indefinite length, a length past
    /// the bytes, an integer or length not in its shortest form, a key
    /// that isn't a string or is out of canonical order (a repeat
    /// included), a float that isn't 64-bit or finite, another simple
    /// value, another tag, a tag 42 whose content isn't a CID, or bytes
    /// after the map.
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
    /// Anything else, validated and skipped.
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

    /// A head: major type and argument, in its shortest form. Indefinite
    /// lengths and the reserved additional values are refused; for major
    /// 7, only `false`, `true`, `null` and a finite 64-bit float.
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
        if major == 7 {
            return match ai {
                20..=22 => Ok((major, arg)),
                // Finite, and not negative zero (DAG-CBOR's strictness).
                27 if f64::from_bits(arg).is_finite() && arg != 0x8000_0000_0000_0000 => {
                    Ok((major, arg))
                }
                _ => Err(Error::Malformed),
            };
        }
        // The shortest form: each wider argument only for a value the
        // narrower one can't hold.
        let shortest = match ai {
            24 => arg >= 24,
            25 => arg > 0xff,
            26 => arg > 0xffff,
            27 => arg > 0xffff_ffff,
            _ => true,
        };
        if !shortest {
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

    fn text(&mut self, len: u64) -> Result<&'a str, Error> {
        std::str::from_utf8(self.take_len(len)?).map_err(|_| Error::Malformed)
    }

    /// A container's items: a count past the bytes left can't be met,
    /// since each item takes at least a byte.
    fn items(&self, major: u8, arg: u64) -> Result<u64, Error> {
        let items = if major == 5 {
            arg.checked_mul(2).ok_or(Error::Malformed)?
        } else {
            arg
        };
        if items > (self.b.len() - self.at) as u64 {
            return Err(Error::Malformed);
        }
        Ok(items)
    }

    /// Tag 42's content: a byte string of 0x00 and one whole CID.
    fn link(&mut self) -> Result<(), Error> {
        let (major, len) = self.head()?;
        if major != 2 {
            return Err(Error::Malformed);
        }
        match self.take_len(len)?.split_first() {
            Some((0, cid)) if cid::parse(cid).is_some() => Ok(()),
            _ => Err(Error::Malformed),
        }
    }
}

/// An open container: the items still to read, whether it is a map
/// (whose items alternate key, value), and its last key.
#[derive(Clone, Copy)]
struct Open<'a> {
    left: u64,
    map: bool,
    last_key: Option<&'a [u8]>,
}

/// Canonical order: shorter keys first, then bytewise; strictly, so a
/// repeat is out of order too.
fn in_order(before: &[u8], key: &[u8]) -> bool {
    (before.len(), before) < (key.len(), key)
}

/// A strict DAG-CBOR top-level map, validated whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Map<'a> {
    bytes: &'a [u8],
    len: u64,
}

/// Validates `bytes` as one strict DAG-CBOR top-level map, allocating
/// nothing. Trailing bytes are refused.
pub fn top_map(bytes: &[u8]) -> Result<Map<'_>, Error> {
    let mut r = Reader { b: bytes, at: 0 };
    let (major, count) = r.head()?;
    if major != 5 {
        return Err(Error::Malformed);
    }
    let items = r.items(major, count)?;
    let mut stack = [Open {
        left: 0,
        map: false,
        last_key: None,
    }; MAX_DEPTH];
    stack[0] = Open {
        left: items,
        map: true,
        last_key: None,
    };
    let mut top = 1usize;
    loop {
        while top > 0 && stack[top - 1].left == 0 {
            top -= 1;
        }
        if top == 0 {
            break;
        }
        let open = &mut stack[top - 1];
        let key = open.map && open.left % 2 == 0;
        open.left -= 1;
        let (major, arg) = r.head()?;
        if key {
            if major != 3 {
                return Err(Error::Malformed);
            }
            let key = r.text(arg)?.as_bytes();
            let open = &mut stack[top - 1];
            if open.last_key.is_some_and(|before| !in_order(before, key)) {
                return Err(Error::Malformed);
            }
            open.last_key = Some(key);
            continue;
        }
        match major {
            0 | 1 => {}
            2 => {
                r.take_len(arg)?;
            }
            3 => {
                r.text(arg)?;
            }
            4 | 5 => {
                if top == MAX_DEPTH {
                    return Err(Error::TooDeep);
                }
                stack[top] = Open {
                    left: r.items(major, arg)?,
                    map: major == 5,
                    last_key: None,
                };
                top += 1;
            }
            6 => {
                if arg != 42 {
                    return Err(Error::Malformed);
                }
                r.link()?;
            }
            // Major 7, already checked in `head`.
            _ => {}
        }
    }
    if r.at != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(Map { bytes, len: count })
}

impl<'a> Map<'a> {
    /// The number of entries.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The top-level value under `key`: an unsigned integer, bytes, text,
    /// or [`Item::Other`] for anything else. Keys are unique, so the first
    /// match is the only one.
    pub fn get(&self, key: &str) -> Option<Item<'a>> {
        let mut r = Reader {
            b: self.bytes,
            at: 0,
        };
        r.head().ok()?;
        for _ in 0..self.len {
            let (_, len) = r.head().ok()?;
            let k = r.text(len).ok()?;
            let (major, arg) = r.head().ok()?;
            if k == key {
                return Some(match major {
                    0 => Item::Uint(arg),
                    2 => Item::Bytes(r.take_len(arg).ok()?),
                    3 => Item::Text(r.text(arg).ok()?),
                    _ => Item::Other,
                });
            }
            skip(&mut r, major, arg)?;
        }
        None
    }
}

/// Skips one validated value whose head was read: no stack is needed,
/// only a count of the items still owed.
fn skip(r: &mut Reader<'_>, major: u8, arg: u64) -> Option<()> {
    let mut owed: u64 = 0;
    let (mut major, mut arg) = (major, arg);
    loop {
        match major {
            2 | 3 => {
                r.take_len(arg).ok()?;
            }
            4 => owed = owed.checked_add(arg)?,
            5 => owed = owed.checked_add(arg.checked_mul(2)?)?,
            6 => owed = owed.checked_add(1)?,
            _ => {}
        }
        if owed == 0 {
            return Some(());
        }
        owed -= 1;
        (major, arg) = r.head().ok()?;
    }
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
        for bad in [
            // An indefinite-length map; a length past the end; a repeated
            // key; a non-string key; tag 1; trailing bytes.
            &[0xbf, 0xff][..],
            &[0xa1, 0x61, b'a', 0x59, 0xff, 0xff],
            &[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
            &[0xa1, 0x01, 0x01],
            &[0xa1, 0x61, b'a', 0xc1, 0x01],
            &[0xa0, 0x00],
            // A non-string key, a repeated key and keys out of order in a
            // nested map; b before a at the top; a key a byte longer
            // before a shorter one.
            &[0xa1, 0x61, b'a', 0xa1, 0x01, 0x01],
            &[0xa1, 0x61, b'a', 0xa2, 0x61, b'x', 0x01, 0x61, b'x', 0x01],
            &[0xa1, 0x61, b'a', 0xa2, 0x61, b'y', 0x01, 0x61, b'x', 0x01],
            &[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x01],
            &[0xa2, 0x62, b'a', b'a', 0x01, 0x61, b'b', 0x01],
            // Tag 42 over an integer, over bytes without the 0x00 prefix,
            // over 0x00 alone, over 0x00 and bytes that aren't a CID, and
            // over a CID whose version isn't minimal.
            &[0xa1, 0x61, b'a', 0xd8, 0x2a, 0x01],
            &[0xa1, 0x61, b'a', 0xd8, 0x2a, 0x41, 0x01],
            &[0xa1, 0x61, b'a', 0xd8, 0x2a, 0x41, 0x00],
            &[0xa1, 0x61, b'a', 0xd8, 0x2a, 0x44, 0x00, 0x07, 0x07, 0x07],
            &[
                0xa1, 0x61, b'a', 0xd8, 0x2a, 0x46, 0x00, 0x81, 0x00, 0x55, 0x00, 0x00,
            ],
            // Not the shortest form: 1 in two bytes, a key's length in two
            // bytes, 255 in three.
            &[0xa1, 0x61, b'a', 0x18, 0x01],
            &[0xa1, 0x78, 0x01, b'a', 0x01],
            &[0xa1, 0x61, b'a', 0x19, 0x00, 0xff],
            // Floats: NaN, infinity, negative zero, a 32-bit float; and
            // undefined.
            &[0xa1, 0x61, b'a', 0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0],
            &[0xa1, 0x61, b'a', 0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0],
            &[0xa1, 0x61, b'a', 0xfb, 0x80, 0, 0, 0, 0, 0, 0, 0],
            &[0xa1, 0x61, b'a', 0xfa, 0x3f, 0xc0, 0, 0],
            &[0xa1, 0x61, b'a', 0xf7],
        ] {
            assert_eq!(top_map(bad), Err(Error::Malformed), "{bad:02x?}");
        }
    }

    #[test]
    fn values() {
        let bytes = [
            0xa4, 0x61, b'a', 0x18, 0x2a, 0x61, b'b', 0x42, 1, 2, 0x61, b'c', 0xf5, 0x61, b'd',
            0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0,
        ];
        let m = top_map(&bytes).unwrap_or(Map { bytes: &[], len: 0 });
        assert_eq!(m.len(), 4);
        assert_eq!(m.get("a"), Some(Item::Uint(42)));
        assert_eq!(m.get("b"), Some(Item::Bytes(&[1, 2])));
        assert_eq!(m.get("c"), Some(Item::Other));
        assert_eq!(m.get("d"), Some(Item::Other));
        assert_eq!(m.get("e"), None);
        // A link where DAG-CBOR allows one: 0x00, then a CID (CIDv1, raw,
        // an empty identity digest), here inside a nested map; the key
        // after it is still found.
        let m = top_map(&[
            0xa2, 0x61, b'l', 0xa1, 0x61, b'x', 0xd8, 0x2a, 0x45, 0x00, 0x01, 0x55, 0x00, 0x00,
            0x61, b'z', 0x07,
        ]);
        assert_eq!(
            m.map(|m| (m.get("l"), m.get("z"))),
            Ok((Some(Item::Other), Some(Item::Uint(7))))
        );
    }
}
