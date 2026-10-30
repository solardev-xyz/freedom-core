//! IPNS records (0009, IPNS and DNSLink), checked as freedom-ipfs's
//! `verify_ipns_record` checks them, with bounded decoding and the
//! stricter key rules: the name's key in libp2p's deterministic encoding,
//! Ed25519 checked non-strictly as freedom-ipfs and Go's `crypto/ed25519`
//! check it, and RSA keys of 2,048 to 8,192 bits checked with the `rsa`
//! crate, verification only.

use ed25519_dalek::Verifier;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use crate::Refusal;
use crate::cbor::{self, Item};
use crate::cid::{Cid, IDENTITY, LIBP2P_KEY, SHA2_256};
use crate::der;
use crate::pb::{self, Value};
use crate::rfc3339;

/// The largest record read.
pub const MAX_RECORD: usize = 10 * 1024;
const SIGNED_PREFIX: &[u8] = b"ipns-signature:";
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// libp2p's key types (the peer-ID specification, *Keys*).
const RSA: u64 = 0;
const ED25519: u64 = 1;
/// go-libp2p's bounds, which rust-libp2p's ring also holds above.
const MIN_RSA_BITS: usize = 2048;
const MAX_RSA_BITS: usize = 8192;
const MAX_RSA_EXPONENT: u64 = (1 << 33) - 1;

/// A record that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// `/ipfs/…` or `/ipns/…`.
    pub value: String,
    pub sequence: u64,
    pub validity: String,
    pub ttl_ns: u64,
}

const FAIL: Refusal = Refusal::VerificationFailed;

/// A libp2p `PublicKey` in its deterministic encoding only: `Type`, then
/// `Data`, both present, minimal varints, nothing else.
fn public_key(proto: &[u8]) -> Result<(u64, &[u8]), Refusal> {
    let mut f = pb::fields(proto);
    let (Some(Ok((1, Value::Varint(kind)))), Some(Ok((2, Value::Bytes(data)))), None) =
        (f.next(), f.next(), f.next())
    else {
        return Err(FAIL);
    };
    // Minimal varints: re-encode the two heads and the type and compare.
    let mut canonical = vec![0x08];
    push_varint(kind, &mut canonical);
    canonical.push(0x12);
    push_varint(data.len() as u64, &mut canonical);
    canonical.extend_from_slice(data);
    if canonical != proto {
        return Err(FAIL);
    }
    Ok((kind, data))
}

fn push_varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The record's fields the check reads, as views.
#[derive(Default)]
struct Entry<'a> {
    value: Option<&'a [u8]>,
    validity_type: Option<u64>,
    validity: Option<&'a [u8]>,
    sequence: Option<u64>,
    ttl: Option<u64>,
    pub_key: Option<&'a [u8]>,
    /// Whether a non-empty `signatureV1` came: with a non-empty legacy
    /// `value`, it asks for every legacy field to match.
    signature_v1: bool,
    signature_v2: Option<&'a [u8]>,
    data: Option<&'a [u8]>,
}

fn entry(record: &[u8]) -> Result<Entry<'_>, Refusal> {
    let mut e = Entry::default();
    for field in pb::fields(record) {
        match field.map_err(|()| FAIL)? {
            (1, Value::Bytes(v)) => e.value = Some(v),
            (2, Value::Bytes(v)) => e.signature_v1 = !v.is_empty(),
            (3, Value::Varint(v)) => e.validity_type = Some(v),
            (4, Value::Bytes(v)) => e.validity = Some(v),
            (5, Value::Varint(v)) => e.sequence = Some(v),
            (6, Value::Varint(v)) => e.ttl = Some(v),
            (7, Value::Bytes(v)) => e.pub_key = Some(v),
            (8, Value::Bytes(v)) => e.signature_v2 = Some(v),
            (9, Value::Bytes(v)) => e.data = Some(v),
            (1..=9, _) => return Err(FAIL),
            _ => {}
        }
    }
    Ok(e)
}

fn verify_rsa(spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Refusal> {
    let (n, e) = der::rsa_spki(spki).ok_or(FAIL)?;
    let n = rsa::BigUint::from_bytes_be(n);
    let bits = n.bits();
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
        return Err(FAIL);
    }
    let e_value = e.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    if !(3..=MAX_RSA_EXPONENT).contains(&e_value) || e_value % 2 == 0 {
        return Err(FAIL);
    }
    let key = rsa::RsaPublicKey::new_with_max_size(n, rsa::BigUint::from(e_value), MAX_RSA_BITS)
        .map_err(|_| FAIL)?;
    // Exactly as long as the modulus (RFC 8017, 8.2.2).
    if signature.len() != key.size() {
        return Err(FAIL);
    }
    let scheme = rsa::Pkcs1v15Sign {
        hash_len: Some(32),
        prefix: SHA256_DIGEST_INFO.into(),
    };
    key.verify(scheme, &Sha256::digest(message), signature)
        .map_err(|_| FAIL)
}

fn verify_ed25519(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Refusal> {
    let key: [u8; 32] = key.try_into().map_err(|_| FAIL)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| FAIL)?;
    let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| FAIL)?;
    // Non-strict, as freedom-ipfs (libp2p-identity) and Go check it: a key
    // of small order isn't refused. A name commits to its key, so a weak
    // key weakens only its owner's own name.
    key.verify(message, &sig).map_err(|_| FAIL)
}

/// Checks `record`, served for `name` (a libp2p-key CID), at `now` (Unix
/// seconds). An inlined key other than Ed25519 never gets here (the plan
/// leaves it a fetch); a hashed name's key other than RSA is unverifiable.
pub fn check(name: &Cid<'_>, record: &[u8], now: i64) -> Result<Record, Refusal> {
    if record.len() > MAX_RECORD || name.codec != LIBP2P_KEY {
        return Err(FAIL);
    }
    let e = entry(record)?;
    let signature = e.signature_v2.filter(|s| !s.is_empty()).ok_or(FAIL)?;
    let data = e.data.filter(|d| !d.is_empty()).ok_or(FAIL)?;
    // The key: inlined in the name, or carried in pubKey and hashing to it.
    let proto = match name.hash {
        IDENTITY => {
            if let Some(k) = e.pub_key
                && k != name.digest
            {
                return Err(FAIL);
            }
            name.digest
        }
        SHA2_256 => {
            let k = e.pub_key.ok_or(FAIL)?;
            if Sha256::digest(k).as_slice() != name.digest {
                return Err(FAIL);
            }
            k
        }
        _ => return Err(Refusal::Unverifiable),
    };
    let (kind, key) = public_key(proto)?;
    let mut message = SIGNED_PREFIX.to_vec();
    message.extend_from_slice(data);
    // An Ed25519 key is inlined in its name; an RSA key, too large to
    // inline, is hashed into it. Any other pairing, a hashed Ed25519 key
    // included, is no name libp2p makes (0009, IPNS and DNSLink).
    match (name.hash, kind) {
        (IDENTITY, ED25519) => verify_ed25519(key, &message, signature)?,
        (SHA2_256, RSA) => verify_rsa(key, &message, signature)?,
        _ => return Err(Refusal::Unverifiable),
    }
    // The signed data, then the legacy fields against it. The signature
    // has passed, so data the strict reader can't take (outside DAG-CBOR's
    // strict profile, a length past the end, nesting past the bound) is
    // the signer's: unverifiable, not a lie (0009, IPNS and DNSLink).
    let map = cbor::top_map(data).map_err(|_| Refusal::Unverifiable)?;
    let get = |k: &str| map.get(k);
    let (
        Some(Item::Bytes(value)),
        Some(Item::Bytes(validity)),
        Some(Item::Uint(validity_type)),
        Some(Item::Uint(sequence)),
        Some(Item::Uint(ttl)),
    ) = (
        get("Value"),
        get("Validity"),
        get("ValidityType"),
        get("Sequence"),
        get("TTL"),
    )
    else {
        return Err(FAIL);
    };
    // Each legacy field present equals its signed counterpart, as the
    // native reader checks; and once `signatureV1` or the legacy value is
    // non-empty, all five do, an absent one read as its protobuf default,
    // as the IPNS record specification and boxo require (deviation
    // `ipns-legacy-fields`).
    if e.value.is_some_and(|v| v != value)
        || e.validity.is_some_and(|v| v != validity)
        || e.validity_type.is_some_and(|v| v != validity_type)
        || e.sequence.is_some_and(|v| v != sequence)
        || e.ttl.is_some_and(|v| v != ttl)
    {
        return Err(FAIL);
    }
    let legacy = e.signature_v1 || e.value.is_some_and(|v| !v.is_empty());
    if legacy
        && (e.value.unwrap_or_default() != value
            || e.validity.unwrap_or_default() != validity
            || e.validity_type.unwrap_or(0) != validity_type
            || e.sequence.unwrap_or(0) != sequence
            || e.ttl.unwrap_or(0) != ttl)
    {
        return Err(FAIL);
    }
    if validity_type != 0 {
        return Err(FAIL);
    }
    let validity = std::str::from_utf8(validity).map_err(|_| FAIL)?;
    let (eol, nanos) = rfc3339::parse(validity).ok_or(FAIL)?;
    if eol < now || (eol == now && nanos == 0) {
        return Err(FAIL);
    }
    let value = std::str::from_utf8(value).map_err(|_| FAIL)?;
    if !value.starts_with("/ipfs/") && !value.starts_with("/ipns/") {
        return Err(FAIL);
    }
    Ok(Record {
        value: value.to_owned(),
        sequence,
        validity: validity.to_owned(),
        ttl_ns: ttl,
    })
}
