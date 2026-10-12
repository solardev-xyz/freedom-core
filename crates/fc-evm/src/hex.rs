use crate::Error;

/// `0x`-prefixed hex with an even number of digits, either case (ethers'
/// `getBytes` takes `0x` or `0X`).
pub fn parse_bytes(text: &str, what: &str) -> Result<Vec<u8>, Error> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .ok_or_else(|| Error::Value(format!("{what}: expected 0x-prefixed hex")))?;
    if !digits.len().is_multiple_of(2) {
        return Err(Error::Value(format!("{what}: odd number of hex digits")));
    }
    // from_str_radix alone would take a sign.
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Value(format!("{what}: not hex")));
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| {
            digits
                .get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| Error::Value(format!("{what}: not hex")))
        })
        .collect()
}

/// Lowercase `0x` hex.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(parse_bytes("0x", "v").unwrap(), Vec::<u8>::new());
        assert_eq!(parse_bytes("0XAbCd", "v").unwrap(), vec![0xab, 0xcd]);
        for bad in ["", "abcd", "0xabc", "0xzz", "0x+1", "0x 1"] {
            assert!(parse_bytes(bad, "v").is_err(), "{bad:?}");
        }
        assert_eq!(to_hex(&[0, 0xff]), "0x00ff");
    }
}
