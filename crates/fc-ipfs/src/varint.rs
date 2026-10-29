//! Unsigned LEB128 varints, at most 10 bytes, as protobuf, multiformats
//! and CAR framing write them.

/// The longest varint read.
pub const MAX_LEN: usize = 10;

/// Reads a varint from the front of `bytes`: its value and length. `None`
/// when it runs past the bytes, past 10 bytes, or past 64 bits.
pub fn read(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().enumerate().take(MAX_LEN) {
        let low = u64::from(b & 0x7f);
        if i == 9 && low > 1 {
            return None;
        }
        value |= low << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_bounds() {
        assert_eq!(read(&[0x00]), Some((0, 1)));
        assert_eq!(read(&[0xac, 0x02]), Some((300, 2)));
        assert_eq!(read(&[0x80]), None);
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(read(&max), Some((u64::MAX, 10)));
        let past = [
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ];
        assert_eq!(read(&past), None);
        let wide = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(read(&wide), None);
    }
}
