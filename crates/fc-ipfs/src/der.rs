//! The one DER structure verified mode reads: an RSA key's PKIX
//! `SubjectPublicKeyInfo` (0009, IPNS and DNSLink; Bounded decoding), in
//! canonical DER only, at a fixed depth, without recursion. Lengths are
//! definite and in their shortest form, each checked against the bytes
//! remaining; integers are positive and minimal.

/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// The largest modulus read: 8,192 bits (and a leading zero byte).
const MAX_MODULUS: usize = 8192 / 8 + 1;
/// The largest exponent read: 33 bits.
const MAX_EXPONENT: usize = 5;

/// One TLV: its tag, its contents, and what follows.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 3 {
            return None;
        }
        let bytes = rest.get(..n)?;
        // Shortest form: no leading zero, and long form only past 127.
        if bytes[0] == 0 {
            return None;
        }
        let len = bytes
            .iter()
            .fold(0usize, |acc, &x| (acc << 8) | usize::from(x));
        if len < 0x80 {
            return None;
        }
        (len, &rest[n..])
    };
    let contents = rest.get(..len)?;
    Some((tag, contents, &rest[len..]))
}

fn expect(b: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (t, c, rest) = tlv(b)?;
    (t == tag).then_some((c, rest))
}

/// A positive, minimally encoded INTEGER of at most `max` bytes: its
/// magnitude, without a leading zero.
fn uint(b: &[u8], max: usize) -> Option<(&[u8], &[u8])> {
    let (c, rest) = expect(b, 0x02)?;
    if c.is_empty() || c.len() > max || c[0] & 0x80 != 0 {
        return None;
    }
    if c.len() > 1 && c[0] == 0 && c[1] & 0x80 == 0 {
        return None;
    }
    let magnitude = if c[0] == 0 { &c[1..] } else { c };
    Some((magnitude, rest))
}

/// An RSA public key's modulus and exponent (big-endian magnitudes) from a
/// canonical DER `SubjectPublicKeyInfo`; `None` for anything else.
pub fn rsa_spki(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (spki, rest) = expect(der, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (alg, after) = expect(spki, 0x30)?;
    let (oid, params) = expect(alg, 0x06)?;
    if oid != RSA_OID {
        return None;
    }
    let (null, end) = expect(params, 0x05)?;
    if !null.is_empty() || !end.is_empty() {
        return None;
    }
    let (bits, end) = expect(after, 0x03)?;
    if !end.is_empty() {
        return None;
    }
    let (&unused, key) = bits.split_first()?;
    if unused != 0 {
        return None;
    }
    let (seq, end) = expect(key, 0x30)?;
    if !end.is_empty() {
        return None;
    }
    let (n, rest) = uint(seq, MAX_MODULUS)?;
    let (e, end) = uint(rest, MAX_EXPONENT)?;
    end.is_empty().then_some((n, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_in_their_shortest_form() {
        assert!(tlv(&[0x04, 0x01, 0xaa]).is_some());
        // 1 in long form, a leading zero in a long length, indefinite.
        assert!(tlv(&[0x04, 0x81, 0x01, 0xaa]).is_none());
        assert!(tlv(&[0x04, 0x82, 0x00, 0x80]).is_none());
        assert!(tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
        // Past the bytes.
        assert!(tlv(&[0x04, 0x05, 0xaa]).is_none());
    }

    #[test]
    fn integers_positive_and_minimal() {
        assert_eq!(uint(&[0x02, 0x01, 0x03], 5).map(|x| x.0), Some(&[3u8][..]));
        assert_eq!(
            uint(&[0x02, 0x02, 0x00, 0x80], 5).map(|x| x.0),
            Some(&[0x80u8][..])
        );
        assert!(uint(&[0x02, 0x02, 0x00, 0x01], 5).is_none());
        assert!(uint(&[0x02, 0x01, 0x80], 5).is_none());
        assert!(uint(&[0x02, 0x00], 5).is_none());
        assert!(uint(&[0x02, 0x06, 1, 2, 3, 4, 5, 6], 5).is_none());
    }
}
