//! Recursive-length prefix encoding, as Ethereum transactions use it.

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
}
