//! A broadcast's transaction hash: keccak-256 of the signed bytes, compared
//! as 32-byte values whatever the hex case (design 0005, Broadcast).
//!
//! Nothing here allocates: a raw transaction is hashed as its hex is read,
//! and a purported hash is read into 32 bytes, refused at its 65th digit.
//! An answer can be as large as the answer cap.

use sha3::{Digest as _, Keccak256};

/// A transaction hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxHash([u8; 32]);

/// The raw transaction is not hex bytes: `0x` (or `0X`) and an even number
/// of hex digits, as ethers' `keccak256` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the raw transaction is not 0x-prefixed hex bytes")]
pub struct NotHex;

/// The hash of a raw signed transaction given as hex, hashed as it is
/// read.
pub fn transaction_hash(raw: &str) -> Result<TxHash, NotHex> {
    let digits = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or(NotHex)?;
    if digits.len() % 2 != 0 {
        return Err(NotHex);
    }
    let mut hasher = Keccak256::new();
    let mut buffer = [0u8; 512];
    for chunk in digits.as_bytes().chunks(2 * buffer.len()) {
        let bytes = buffer.get_mut(..chunk.len() / 2).ok_or(NotHex)?;
        for (byte, pair) in bytes.iter_mut().zip(chunk.chunks(2)) {
            *byte = match pair {
                [high, low] => (nibble(*high).ok_or(NotHex)? << 4) | nibble(*low).ok_or(NotHex)?,
                _ => return Err(NotHex),
            };
        }
        hasher.update(&*bytes);
    }
    Ok(TxHash(hasher.finalize().into()))
}

/// A hex digit's value.
fn nibble(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// Reads `0x` (or `0X`) and exactly 64 hex digits, unit by unit, into 32
/// bytes: `None` at the first unit that can't belong, the 65th digit
/// included.
fn read_hash(mut units: impl Iterator<Item = Option<u16>>) -> Option<[u8; 32]> {
    let mut next = || units.next().flatten();
    if next()? != u16::from(b'0') || !matches!(next()?, 0x78 | 0x58) {
        return None;
    }
    let mut hash = [0u8; 32];
    for byte in &mut hash {
        let high = nibble(u8::try_from(next()?).ok()?)?;
        let low = nibble(u8::try_from(next()?).ok()?)?;
        *byte = (high << 4) | low;
    }
    Some(hash)
}

/// JSON's whitespace.
fn is_json_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// A JSON string's units, escapes decoded, stopping at its closing quote;
/// `None` for one that isn't valid JSON (and nothing more is read). `end`
/// is set to the closing quote's offset.
struct JsonUnits<'t> {
    bytes: &'t [u8],
    at: usize,
    end: Option<usize>,
}

impl Iterator for JsonUnits<'_> {
    type Item = Option<u16>;

    fn next(&mut self) -> Option<Option<u16>> {
        if self.end.is_some() {
            return None;
        }
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(match byte {
            b'"' => {
                self.end = Some(self.at - 1);
                return None;
            }
            b'\\' => {
                let escape = *self.bytes.get(self.at)?;
                self.at += 1;
                match escape {
                    b'"' | b'\\' | b'/' => Some(u16::from(escape)),
                    b'b' => Some(0x08),
                    b'f' => Some(0x0c),
                    b'n' => Some(0x0a),
                    b'r' => Some(0x0d),
                    b't' => Some(0x09),
                    b'u' => {
                        let digits = self.bytes.get(self.at..self.at + 4)?;
                        self.at += 4;
                        digits.iter().try_fold(0u16, |unit, digit| {
                            Some((unit << 4) | u16::from(nibble(*digit)?))
                        })
                    }
                    _ => None,
                }
            }
            // A control character can't stand in a JSON string; any other
            // non-ASCII text can, but no hash holds it.
            0x20..=0x7f => Some(u16::from(byte)),
            _ => None,
        })
    }
}

impl TxHash {
    /// A hash written as `0x` (or `0X`) and 64 hex digits, any case.
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 66 {
            return None;
        }
        read_hash(text.bytes().map(|b| Some(u16::from(b)))).map(Self)
    }

    /// A hash given as a JSON value's text: a string holding
    /// [`Self::from_hex`]'s form (escapes and all), between JSON
    /// whitespace. Read in place, never indexed: a value that can't be a
    /// hash is refused at its first unit that can't belong.
    pub fn from_json(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let start = bytes.iter().position(|b| !is_json_space(*b))?;
        if bytes.get(start) != Some(&b'"') {
            return None;
        }
        let mut units = JsonUnits {
            bytes,
            at: start + 1,
            end: None,
        };
        let hash = read_hash(&mut units)?;
        // The string ends right after its 64th digit, and only whitespace
        // follows it.
        if units.next().is_some() {
            return None;
        }
        let end = units.end?;
        bytes
            .get(end + 1..)?
            .iter()
            .all(|b| is_json_space(*b))
            .then_some(Self(hash))
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

    /// The readings these replace, which indexed and copied the whole
    /// value: the new ones must agree with them everywhere.
    fn indexed_from_json(text: &str) -> Option<TxHash> {
        let index = fc_json::index::Index::new(text).ok()?;
        let root = index.root();
        if root.kind() != fc_json::index::Kind::String {
            return None;
        }
        let units: Vec<u16> = root.units().collect();
        TxHash::from_hex(&String::from_utf16(&units).ok()?)
    }

    fn copied_hash(raw: &str) -> Option<TxHash> {
        let digits = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X"))?;
        if digits.len() % 2 != 0 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let bytes: Option<Vec<u8>> = digits
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect();
        Some(TxHash(Keccak256::digest(bytes?).into()))
    }

    #[test]
    fn hashes_are_read_in_place_as_before() {
        let hex = transaction_hash("0x02").unwrap().to_hex();
        let digits = &hex[2..];
        // Escapes built at run time, so this source holds none to decode.
        let escaped = |unit: u32| format!("{}u{unit:04x}", '\\');
        let texts = [
            format!("\"{hex}\""),
            format!(" \t\r\n\"{hex}\" \n"),
            format!("\"0X{}\"", digits.to_uppercase()),
            format!("\"{}{}\"", escaped(0x30), &hex[1..]),
            format!("\"{}{}\"", &hex[..65], escaped(0x66)),
            format!("\"{}\\/\"", &hex[..65]),
            format!("\"{hex}0\""),
            format!("\"{}\"", &hex[..65]),
            format!("\"{hex}\" x"),
            format!("\"{hex}\"\""),
            format!("\"{hex}"),
            hex.clone(),
            format!("[\"{hex}\"]"),
            format!("\"{}{}\"", &hex[..64], escaped(0xd800)),
            format!("\"{}\u{e9}\"", &hex[..65]),
            format!("\"0x{}\"", "g".repeat(64)),
            format!("\"{}\\q\"", &hex[..65]),
            format!("\"{}\\u12\"", &hex[..64]),
            String::new(),
            "null".into(),
            "\"\"".into(),
            "\"0x\"".into(),
            format!("\"0x{}\"", "a".repeat(100_000)),
        ];
        for text in &texts {
            assert_eq!(TxHash::from_json(text), indexed_from_json(text), "{text}");
        }
        assert!(TxHash::from_json(&texts[0]).is_some());
        assert!(TxHash::from_json(&texts[3]).is_some());
        for raw in [
            "0x", "0x02", "0XAbCd", "0x0", "0x0g", "02", " 0x02", "0x\u{e9}",
        ] {
            assert_eq!(transaction_hash(raw).ok(), copied_hash(raw), "{raw}");
        }
        // Longer than the read buffer, odd chunks included.
        for len in [511, 512, 513, 1_024, 1_025, 4_097] {
            let raw = format!("0x{}", "a1".repeat(len));
            assert_eq!(transaction_hash(&raw).ok(), copied_hash(&raw), "{len}");
        }
    }
}
