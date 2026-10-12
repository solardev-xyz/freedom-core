//! ENSIP-7 contenthash decoding, exactly as `parseContentHashBytes` in
//! `ens-resolver.js` does it, quirks included:
//!
//! - an `ipfs-ns` dag-pb hash with a one-byte multihash header is kept as
//!   CIDv0 base58 (`Qm…`), so names users already visited keep their history
//!   and bookmarks. The multihash code isn't checked;
//! - any other `ipfs-ns` CIDv1 becomes base32 (`b…`);
//! - `ipns-ns` is the base58 multihash (`12D3Koo…`), converted to a CID later
//!   by the protocol handler;
//! - `swarm-ns` is the 32-byte reference in hex;
//! - anything else is unsupported.

/// A decoded contenthash: `uri` is `{protocol}://{decoded}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub codec: &'static str,
    pub protocol: &'static str,
    pub decoded: String,
}

impl Content {
    pub fn uri(&self) -> String {
        format!("{}://{}", self.protocol, self.decoded)
    }
}

const IPFS_DAG_PB: [u8; 4] = [0xe3, 0x01, 0x01, 0x70];
const IPFS_NS: [u8; 2] = [0xe3, 0x01];
const IPNS_LIBP2P_KEY: [u8; 4] = [0xe5, 0x01, 0x01, 0x72];
const SWARM_MANIFEST: [u8; 7] = [0xe4, 0x01, 0x01, 0xfa, 0x01, 0x1b, 0x20];

/// Decodes the inner `bytes` of a `contenthash()` answer. `None` is
/// `UNSUPPORTED_CONTENTHASH_FORMAT`; the caller handles empty bytes
/// (`EMPTY_CONTENTHASH`) before this.
pub fn parse_contenthash(bytes: &[u8]) -> Option<Content> {
    // The rules run in the JS's order, and a rule whose lengths don't check
    // out falls through to the next one.
    if let Some(multihash) = one_byte_multihash(bytes, &IPFS_DAG_PB) {
        return Some(Content {
            codec: "ipfs-ns",
            protocol: "ipfs",
            decoded: encode_base58(multihash),
        });
    }
    // The JS pattern needs "01" and at least one more hex digit.
    if let Some(cid) = bytes.strip_prefix(&IPFS_NS)
        && cid.first() == Some(&0x01)
        && cid.len() >= 2
        && let Some(decoded) = cid_v1_bytes_to_base32(cid)
    {
        return Some(Content {
            codec: "ipfs-ns",
            protocol: "ipfs",
            decoded,
        });
    }
    if let Some(multihash) = one_byte_multihash(bytes, &IPNS_LIBP2P_KEY) {
        return Some(Content {
            codec: "ipns-ns",
            protocol: "ipns",
            decoded: encode_base58(multihash),
        });
    }
    if let Some(reference) = bytes.strip_prefix(&SWARM_MANIFEST)
        && reference.len() == 32
    {
        return Some(Content {
            codec: "swarm-ns",
            protocol: "bzz",
            decoded: to_hex(reference),
        });
    }
    None
}

/// After `prefix`: a one-byte code, a one-byte length, and a digest of
/// exactly that length. Returns the multihash (code, length, digest).
fn one_byte_multihash<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let multihash = bytes.strip_prefix(prefix)?;
    let (&length, digest) = multihash.get(1..)?.split_first()?;
    (digest.len() == usize::from(length)).then_some(multihash)
}

/// `cidV1BytesToBase32` in `cid-utils.js`: a CIDv1 (version, codec varint,
/// multihash code varint, digest length varint, digest) whose total length
/// matches exactly, as `b` + RFC 4648 base32 (lowercase, unpadded).
pub fn cid_v1_bytes_to_base32(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 || bytes[0] != 0x01 {
        return None;
    }
    let (_, codec_len) = read_uvarint(bytes, 1)?;
    let (_, code_len) = read_uvarint(bytes, 1 + codec_len)?;
    let (digest_len, len_len) = read_uvarint(bytes, 1 + codec_len + code_len)?;
    let header = i64::try_from(1 + codec_len + code_len + len_len).ok()?;
    let total = i64::try_from(bytes.len()).ok()?;
    (header + i64::from(digest_len) == total).then(|| format!("b{}", base32(bytes)))
}

/// `readUvarint` in `cid-utils.js`, with JavaScript's 32-bit integer
/// arithmetic: at most five bytes, bits past 31 dropped, and a set bit 31
/// makes the value negative (which then never matches a length).
fn read_uvarint(bytes: &[u8], offset: usize) -> Option<(i32, usize)> {
    let mut value: i32 = 0;
    let mut shift = 0u32;
    let mut pos = offset;
    while let Some(&byte) = bytes.get(pos) {
        pos += 1;
        value |= i32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, pos - offset));
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    None
}

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut value: u32 = 0;
    let mut bits = 0u32;
    for &byte in bytes {
        value = ((value & 0xff) << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            out.push(char::from(
                BASE32_ALPHABET[((value >> (bits - 5)) & 0x1f) as usize],
            ));
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(char::from(
            BASE32_ALPHABET[((value << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// ethers' `encodeBase58`: the big-endian number in base 58, plus a `1` per
/// leading zero byte.
pub fn encode_base58(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // Base-58 digits, least significant first.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &bytes[zeros..] {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(
        digits
            .iter()
            .rev()
            .map(|&d| char::from(BASE58_ALPHABET[usize::from(d)])),
    );
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(hex: &str) -> Option<Content> {
        parse_contenthash(&hex::decode(hex.trim_start_matches("0x")).unwrap())
    }

    #[test]
    fn ipfs_dag_pb_stays_cid_v0() {
        let content =
            parse("0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f")
                .unwrap();
        assert_eq!(content.codec, "ipfs-ns");
        assert_eq!(
            content.uri(),
            "ipfs://QmW81r84Aihiqqi2Jw6nM1LnpeMfRCenRxtjwHNkXVkZYa"
        );
        // The multihash code isn't checked: an identity multihash too.
        assert_eq!(parse("0xe30101700003616263").unwrap().decoded, "161g3c");
    }

    #[test]
    fn ipfs_cid_v1_is_base32() {
        let raw =
            parse("0xe30101551220178009fb926120f294c60ebc3ae54de9dccaace22db785445f6f54a807b322fd")
                .unwrap();
        assert_eq!(
            raw.decoded,
            "bafkreiaxqae7xetbedzjjrqoxq5oktpj3tfkzyrnw6cuix3pksuapmzc7u"
        );
        // Multi-byte codec varint (dag-json).
        let dag_json = format!("0xe30101a9021220{}", "07".repeat(32));
        assert_eq!(
            parse(&dag_json).unwrap().decoded,
            "baguqeeraa4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dq"
        );
        // A dag-pb hash whose one-byte length doesn't match falls through to
        // the varint rule, where it can.
        assert_eq!(parse("0xe3010170128100aa").unwrap().decoded, "bafybfaiavi");
        // A length with bit 31 set is negative in JavaScript: never matches.
        assert_eq!(
            parse("0xe3010170 12ffffffff0f".replace(' ', "").as_str()),
            None
        );
    }

    #[test]
    fn ipns_is_base58_multihash() {
        let content = parse("0xe50101720024080112202ffa35a99d3a3cfbb17bb7c1dc5561b18a8dcca4df38dc613ea859c37eb1336b").unwrap();
        assert_eq!(
            content.uri(),
            "ipns://12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"
        );
    }

    #[test]
    fn swarm_reference_is_hex() {
        let reference = "ab".repeat(32);
        let content = parse(&format!("0xe40101fa011b20{reference}")).unwrap();
        assert_eq!(content.uri(), format!("bzz://{reference}"));
        assert_eq!(parse(&format!("0xe40101fa011b20{reference}00")), None);
    }

    #[test]
    fn everything_else_is_unsupported() {
        // arweave, onion, a bare CIDv0, truncated prefixes.
        for hex in [
            "0x90b2c60f0000",
            "0xbc037a6a76",
            "0x1220aa",
            "0xe301",
            "0xe30101",
            "0xe3010170",
            "0xe301017012",
        ] {
            assert_eq!(parse(hex), None, "{hex}");
        }
    }
}
