//! Verify plans (design 0009, Verify plans; Strict mode): what a fetch
//! plan for an external backend becomes when its content is verified, what
//! stays a fetch, and strict mode's refusals. `vectors/dweb-verify-plans.json`
//! is the contract; its generator composes the same plans from the
//! reference's fetch plans.

use crate::cid::{base32_decode_lenient, base36_decode, cid_v0_to_v1_base32};
use crate::js;
use crate::plan::{
    Backend, ContentTrust, ErrorPlan, Fetch, Node, Plan, ResponseOp, Root, Trust, Verification,
    Verify,
};

/// Strict mode's message when the backend's verification is off.
pub const STRICT_OFF: &str =
    "This profile loads only verified content, and verification is off for this node";
/// When the gateway serves no verifiable responses (`unsupported`).
pub const STRICT_UNSUPPORTED: &str =
    "This profile loads only verified content, and this gateway doesn't serve verifiable responses";
/// For a DNSLink name.
pub const STRICT_DNSLINK: &str =
    "This profile loads only verified content, and a DNSLink name can't be verified";
/// For an IPNS name with an inlined key other than Ed25519.
pub const STRICT_KEY: &str =
    "This profile loads only verified content, and this IPNS name's key type can't be verified";
/// For an encrypted (128-hex) Swarm reference.
pub const STRICT_ENCRYPTED: &str = "This profile loads only verified content, and an encrypted Swarm reference can't be verified with an external node";

/// Strict mode's five messages, in the order 0009 gives them.
pub const STRICT_MESSAGES: [&str; 5] = [
    STRICT_OFF,
    STRICT_UNSUPPORTED,
    STRICT_DNSLINK,
    STRICT_KEY,
    STRICT_ENCRYPTED,
];

/// The status of strict mode's refusals: the profile's, not a node's.
pub const STRICT_STATUS: u16 = 403;

/// The request headers the verifier honours: the bundled node's.
pub const VERIFY_HEADERS_ANT: [&str; 1] = ["range"];
pub const VERIFY_HEADERS_IPFS: [&str; 2] = ["range", "if-none-match"];

/// Why a request's content stays unverified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unverified {
    Off,
    Unsupported,
    Dnslink,
    Key,
    Encrypted,
}

impl Unverified {
    fn message(self) -> &'static str {
        match self {
            Self::Off => STRICT_OFF,
            Self::Unsupported => STRICT_UNSUPPORTED,
            Self::Dnslink => STRICT_DNSLINK,
            Self::Key => STRICT_KEY,
            Self::Encrypted => STRICT_ENCRYPTED,
        }
    }
}

/// What an IPNS name, as a plan's path carries it, says of its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    /// An inlined Ed25519 key.
    Ed25519,
    /// A sha2-256 multihash: an RSA key, if its record's checks out.
    Sha256,
    /// Another inlined key type (secp256k1, ECDSA).
    OtherKey,
    /// Not a libp2p-key CID: a DNSLink name.
    Dnslink,
}

/// A varint of at most 9 bytes, as the generator's `readVarint` reads it
/// (any encoding, minimal or not): its value and where the next begins.
fn read_varint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &b) in bytes.get(at..)?.iter().take(9).enumerate() {
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, at + i + 1));
        }
    }
    None
}

/// The kind of an IPNS name: base36 (`k…`) or base32 (`b…`), lowercase,
/// decoded to a CIDv1 of the libp2p-key codec whose multihash is a
/// sha2-256 digest of 32 bytes, or an identity holding a `PublicKey`
/// protobuf whose type is Ed25519 (`08 01`). Anything else that decodes
/// as a libp2p-key CID is another key; anything that doesn't is DNSLink.
pub fn ipns_name_kind(name: &str) -> NameKind {
    let bytes = if let Some(rest) = name.strip_prefix('k') {
        base36_decode(rest)
    } else if let Some(rest) = name.strip_prefix('b') {
        base32_decode_lenient(rest)
    } else {
        None
    };
    let Some(bytes) = bytes else {
        return NameKind::Dnslink;
    };
    let Some((version, at)) = read_varint(&bytes, 0) else {
        return NameKind::Dnslink;
    };
    let Some((codec, at)) = read_varint(&bytes, at) else {
        return NameKind::Dnslink;
    };
    let Some((code, at)) = read_varint(&bytes, at) else {
        return NameKind::Dnslink;
    };
    let Some((len, at)) = read_varint(&bytes, at) else {
        return NameKind::Dnslink;
    };
    let whole = (at as u64).checked_add(len) == Some(bytes.len() as u64);
    if version != 1 || codec != 0x72 || !whole {
        return NameKind::Dnslink;
    }
    if code == 0x12 && len == 32 {
        return NameKind::Sha256;
    }
    if code != 0x00 {
        return NameKind::OtherKey;
    }
    match bytes.get(at..at + 2) {
        Some([0x08, 0x01]) => NameKind::Ed25519,
        _ => NameKind::OtherKey,
    }
}

/// A verify plan's IPFS root in its canonical form (0009, Verify plans):
/// a CIDv0 as its CIDv1 in base32, and base32 in either case lowercased;
/// anything else as it is, which validation then refuses.
pub fn canonical_cid(target: &str) -> String {
    if let Some(v1) = cid_v0_to_v1_base32(target) {
        return v1;
    }
    let base32 = target.len() > 1
        && target.as_bytes()[0].eq_ignore_ascii_case(&b'b')
        && target
            .bytes()
            .skip(1)
            .all(|b| b.is_ascii_alphabetic() || (b'2'..=b'7').contains(&b));
    if base32 {
        target.to_ascii_lowercase()
    } else {
        target.to_owned()
    }
}

/// The verify plan for a fetch plan, or why its content stays unverified.
fn derive(fetch: &Fetch, small_text: bool) -> Result<Verify, Unverified> {
    let (path_part, query) = match fetch.path.find('?') {
        Some(at) => (&fetch.path[..at], fetch.path[at..].to_owned()),
        None => (fetch.path.as_str(), String::new()),
    };
    let mut segments = path_part.splitn(4, '/');
    let _ = segments.next();
    let namespace = segments.next().unwrap_or("");
    let target = segments.next().unwrap_or("");
    let below = segments
        .next()
        .map(|rest| format!("/{rest}"))
        .unwrap_or_default();
    let root = match fetch.node {
        Node::Ant if js::utf16_len(target) == 128 => return Err(Unverified::Encrypted),
        Node::Ant => Root::Swarm(target.to_owned()),
        Node::Ipfs if namespace == "ipfs" => Root::Ipfs(canonical_cid(target)),
        Node::Ipfs => match ipns_name_kind(target) {
            NameKind::Dnslink => return Err(Unverified::Dnslink),
            NameKind::OtherKey => return Err(Unverified::Key),
            NameKind::Ed25519 | NameKind::Sha256 => Root::Ipns(target.to_owned()),
        },
    };
    let keep: &[&str] = match fetch.node {
        Node::Ant => &VERIFY_HEADERS_ANT,
        Node::Ipfs => &VERIFY_HEADERS_IPFS,
    };
    let mut response = match fetch.node {
        Node::Ant => vec![ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
        Node::Ipfs => vec![ResponseOp::StripPageState],
    };
    if fetch.node == Node::Ipfs && small_text {
        response.push(ResponseOp::SmallText);
    }
    Ok(Verify {
        node: fetch.node,
        root,
        path: below,
        query,
        headers: fetch
            .headers
            .iter()
            .filter(|(name, _)| keep.contains(&name.as_str()))
            .cloned()
            .collect(),
        retry: fetch.retry.clone(),
        timers: fetch.timers,
        response,
        trust: Trust {
            name: fetch.trust.name.clone(),
            content: ContentTrust::Verified,
        },
    })
}

fn strict_error(cause: Unverified) -> Plan {
    Plan::Error(ErrorPlan::new(STRICT_STATUS, cause.message()))
}

/// What today's fetch plan for `backend` becomes (0009): a verify plan when
/// its verification is on and the content can be verified, else the fetch
/// as it is; or, in strict mode, a 403 where the content would be
/// unverified. `small_text` is the request's: a GET navigation.
pub(crate) fn compose(fetch: Fetch, backend: Backend, small_text: bool) -> Plan {
    let strict = backend.strict();
    let refused = match backend.verification() {
        Verification::On => match derive(&fetch, small_text) {
            Ok(verify) => return Plan::Verify(verify),
            Err(cause) => cause,
        },
        Verification::Unsupported => Unverified::Unsupported,
        Verification::Off => Unverified::Off,
    };
    if strict {
        strict_error(refused)
    } else {
        Plan::Fetch(fetch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_kinds() {
        for (name, kind) in [
            (
                "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8",
                NameKind::Ed25519,
            ),
            (
                "k2k4r8np1qb2z0j9bg52w5u13cdwss35fmh5lbs2wo48be1b8d86b6i3",
                NameKind::Sha256,
            ),
            (
                "bafzaajaiaejcbcq7rmgc2ttpocazfi5uyxlop6ajdivtytk6n5yidevdwtc5nz7y",
                NameKind::Ed25519,
            ),
            ("docs.ipfs.tech", NameKind::Dnslink),
            // Uppercase base36 isn't read: the generator's alphabet is
            // lowercase, so the name is DNSLink's.
            (
                "K51QZI5UQU5DLVJ2BAXNQNDEPEB86CBK3NG7N3I46UZYXZYQJ2XJONZLLNV0V8",
                NameKind::Dnslink,
            ),
            // A dag-pb CIDv1: not the libp2p-key codec.
            (
                "bafybeidon73zkcrwdb5iafqtijxildoonbwnpv7dyd6ef3qdgads2jc4su",
                NameKind::Dnslink,
            ),
            ("", NameKind::Dnslink),
            ("k", NameKind::Dnslink),
        ] {
            assert_eq!(ipns_name_kind(name), kind, "{name}");
        }
    }

    #[test]
    fn canonical_roots() {
        assert_eq!(
            canonical_cid("QmVmkadKS2uvxyD6YJJzd3Umem6SWV7QxYnL7kbpdWAsPS"),
            "bafybeidon73zkcrwdb5iafqtijxildoonbwnpv7dyd6ef3qdgads2jc4su"
        );
        assert_eq!(canonical_cid("BAFYBEIA"), "bafybeia");
        assert_eq!(canonical_cid("zb2rh"), "zb2rh");
        assert_eq!(canonical_cid("b"), "b");
    }
}
