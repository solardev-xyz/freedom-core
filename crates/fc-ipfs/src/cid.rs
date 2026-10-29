//! CIDs and multihashes, as far as verified mode reads them: binary CIDs
//! (v0 and v1) inside blocks and CARs, and the CIDv1 in lowercase base32
//! that a verify plan's root names.

use crate::varint;

pub const DAG_PB: u64 = 0x70;
pub const RAW: u64 = 0x55;
pub const LIBP2P_KEY: u64 = 0x72;
pub const IDENTITY: u64 = 0x00;
pub const SHA2_256: u64 = 0x12;

/// The longest multihash digest read: an identity digest carries data
/// inline, and Kubo inlines at most 32 bytes; libp2p inlines keys of up to
/// 42. Anything longer isn't a CID the walk can meet.
pub const MAX_DIGEST: usize = 128;

/// A CID as views into the bytes it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cid<'a> {
    pub version: u8,
    pub codec: u64,
    pub hash: u64,
    pub digest: &'a [u8],
    /// The CID's own bytes, as a link or a CAR section carries them.
    pub bytes: &'a [u8],
}

impl Cid<'_> {
    /// Whether two CIDs name the same block: their codec and multihash
    /// agree, whatever the version (0009, Blocks and DAGs).
    pub fn same_block(&self, other: &Cid<'_>) -> bool {
        self.codec == other.codec && self.hash == other.hash && self.digest == other.digest
    }
}

/// Reads a binary CID from the front of `bytes`; returns it and the bytes
/// it took. CIDv0 is a bare sha2-256 multihash (`0x12 0x20` and 32 bytes).
pub fn read(bytes: &[u8]) -> Option<(Cid<'_>, usize)> {
    if bytes.len() >= 34 && bytes[0] == 0x12 && bytes[1] == 0x20 {
        return Some((
            Cid {
                version: 0,
                codec: DAG_PB,
                hash: SHA2_256,
                digest: &bytes[2..34],
                bytes: &bytes[..34],
            },
            34,
        ));
    }
    let (version, mut at) = varint::read(bytes)?;
    if version != 1 {
        return None;
    }
    let (codec, n) = varint::read(&bytes[at..])?;
    at += n;
    let (hash, n) = varint::read(&bytes[at..])?;
    at += n;
    let (len, n) = varint::read(&bytes[at..])?;
    at += n;
    let len = usize::try_from(len).ok().filter(|&l| l <= MAX_DIGEST)?;
    let digest = bytes.get(at..at + len)?;
    at += len;
    Some((
        Cid {
            version: 1,
            codec,
            hash,
            digest,
            bytes: &bytes[..at],
        },
        at,
    ))
}

/// Reads a whole binary CID: `None` unless it takes every byte.
pub fn parse(bytes: &[u8]) -> Option<Cid<'_>> {
    read(bytes)
        .filter(|(_, n)| *n == bytes.len())
        .map(|(c, _)| c)
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A CIDv1's bytes from its lowercase base32 text (`b…`, RFC 4648, no
/// padding), the only form a verify plan's root takes. `None` for any
/// other text, or a CID that isn't version 1.
pub fn from_base32(text: &str) -> Option<Vec<u8>> {
    let body = text.strip_prefix('b')?;
    let mut out = Vec::with_capacity(body.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in body.bytes() {
        let v = B32.iter().position(|&x| x == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero padding of fewer than 5 bits.
    if bits >= 5 || acc != 0 {
        return None;
    }
    let cid = parse(&out)?;
    (cid.version == 1).then_some(())?;
    Some(out)
}

/// A CID's text as a verify plan and GatewayCore write it: CIDv1 in
/// lowercase base32; CIDv0 in base58btc.
pub fn to_text(cid: &Cid<'_>) -> String {
    if cid.version == 0 {
        return base58(cid.bytes);
    }
    let mut out = String::from("b");
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in cid.bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base58(bytes: &[u8]) -> String {
    const A: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &b in bytes {
        let mut carry = u32::from(b);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    out.extend(digits.iter().rev().map(|&d| A[usize::from(d)] as char));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips_and_refuses() {
        let text = "bafkreie5iksgmmyl2f4ezy3qhpvlkehhebqtpymbiya5iz6wbtnl2ip33i";
        let bytes = from_base32(text).unwrap_or_default();
        assert_eq!(parse(&bytes).map(|c| to_text(&c)).as_deref(), Some(text));
        // Uppercase, another multibase, a dangling character.
        for bad in [
            "BAFKREIE5IKSGMMYL2F4EZY3QHPVLKEHHEBQTPYMBIYA5IZ6WBTNL2IP33I",
            "zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA",
            "bafkreie5iksgmmyl2f4ezy3qhpvlkehhebqtpymbiya5iz6wbtnl2ip33ia",
        ] {
            assert_eq!(from_base32(bad), None, "{bad}");
        }
    }

    #[test]
    fn v0_and_v1_name_the_same_block() {
        let digest = [7u8; 32];
        let mut v0 = vec![0x12, 0x20];
        v0.extend_from_slice(&digest);
        let mut v1 = vec![0x01, 0x70, 0x12, 0x20];
        v1.extend_from_slice(&digest);
        let (a, b) = (parse(&v0), parse(&v1));
        assert!(
            a.zip(b)
                .is_some_and(|(a, b)| a.same_block(&b) && a.version == 0 && b.version == 1)
        );
    }
}
