//! IPNS records the generator signs itself, from seeded keys and a fixed
//! clock (Kubo's `name publish` reads the wall clock), and freedom-ipfs's
//! verdict on each (`freedom_ipfs_namesys::verify_ipns_record`).
//!
//! The encodings are the IPNS record specification's and libp2p's peer-ID
//! specification's: a `PublicKey` protobuf (`Type`, `Data`), an `IpnsEntry`
//! protobuf, and DAG-CBOR signed data with its keys in canonical order.

use base64::Engine;
use cid::Cid;
use ed25519_dalek::Signer;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rsa::pkcs8::EncodePublicKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Err = Box<dyn std::error::Error>;

/// Validity far from any day the generator runs, so the native verdict
/// doesn't depend on when: the vectors' clock is `meta.clock_unix`.
pub const VALID_EOL: &str = "2099-01-01T00:00:00.000000000Z";
pub const EXPIRED_EOL: &str = "2000-01-01T00:00:00.000000000Z";

fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn pb_bytes(field: u64, bytes: &[u8], out: &mut Vec<u8>) {
    varint(field << 3 | 2, out);
    varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

pub fn pb_varint(field: u64, v: u64, out: &mut Vec<u8>) {
    varint(field << 3, out);
    varint(v, out);
}

pub enum Secret {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    Rsa(Box<rsa::RsaPrivateKey>),
}

pub struct Key {
    pub label: String,
    pub kind: &'static str,
    pub bits: usize,
    pub exponent: u64,
    /// The libp2p `PublicKey` protobuf, in its deterministic encoding.
    pub proto: Vec<u8>,
    /// An RSA key's DER `SubjectPublicKeyInfo`.
    pub spki: Vec<u8>,
    secret: Secret,
}

impl Key {
    pub fn ed25519(label: &str) -> Self {
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed(label));
        let mut proto = Vec::new();
        pb_varint(1, 1, &mut proto);
        pb_bytes(2, sk.verifying_key().as_bytes(), &mut proto);
        Self {
            label: label.to_string(),
            kind: "ed25519",
            bits: 256,
            exponent: 0,
            proto,
            spki: Vec::new(),
            secret: Secret::Ed25519(Box::new(sk)),
        }
    }

    /// An RSA key from a ChaCha20 stream seeded with SHA-256(label).
    pub fn rsa(label: &str, bits: usize, exponent: u64) -> Result<Self, Err> {
        let mut rng = ChaCha20Rng::from_seed(seed(label));
        let sk = rsa::RsaPrivateKey::new_with_exp(&mut rng, bits, &rsa::BigUint::from(exponent))?;
        let spki = sk.to_public_key().to_public_key_der()?;
        let mut proto = Vec::new();
        pb_varint(1, 0, &mut proto);
        pb_bytes(2, spki.as_bytes(), &mut proto);
        Ok(Self {
            label: label.to_string(),
            kind: "rsa",
            bits: sk.n().bits(),
            exponent,
            proto,
            spki: spki.as_bytes().to_vec(),
            secret: Secret::Rsa(Box::new(sk)),
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Err> {
        Ok(match &self.secret {
            Secret::Ed25519(sk) => sk.sign(msg).to_bytes().to_vec(),
            Secret::Rsa(sk) => sk.sign(
                rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                &Sha256::digest(msg),
            )?,
        })
    }

    /// The name: CIDv1, libp2p-key, base36; the key inlined (identity
    /// multihash) when its protobuf is at most 42 bytes, else sha2-256.
    pub fn name(&self) -> Result<String, Err> {
        name_of(&self.proto)
    }

    pub fn describe(&self) -> Value {
        json!({
            "label": self.label,
            "type": self.kind,
            "bits": self.bits,
            "exponent": if self.kind == "rsa" { json!(self.exponent) } else { Value::Null },
            "public_key": base64::engine::general_purpose::STANDARD.encode(&self.proto),
        })
    }
}

pub fn name_of(proto: &[u8]) -> Result<String, Err> {
    let mh = if proto.len() <= 42 {
        multihash::Multihash::<64>::wrap(0x00, proto)?
    } else {
        multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(proto))?
    };
    Ok(Cid::new_v1(0x72, mh).to_string_of_base(multibase::Base::Base36Lower)?)
}

/// What a record says, and how its bytes deviate from a plain V2-only one.
pub struct Spec {
    pub value: String,
    pub validity: String,
    pub sequence: u64,
    pub ttl_ns: u64,
    /// The legacy V1 fields, and their signature.
    pub legacy: bool,
    /// A legacy `value` that differs from the signed one.
    pub legacy_value: Option<String>,
    /// Unknown protobuf fields in the entry, and an unknown key in the data.
    pub unknown: bool,
    pub signature_v2: bool,
    /// Carry the signer's key in `pubKey` (always for RSA).
    pub pub_key: bool,
}

impl Spec {
    pub fn v2(value: &str, sequence: u64) -> Self {
        Self {
            value: value.to_string(),
            validity: VALID_EOL.to_string(),
            sequence,
            ttl_ns: 300_000_000_000,
            legacy: false,
            legacy_value: None,
            unknown: false,
            signature_v2: true,
            pub_key: false,
        }
    }
}

fn cbor_head(major: u8, v: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match v {
        0..=23 => out.push(m | v as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, v as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

fn cbor_text(s: &str, out: &mut Vec<u8>) {
    cbor_head(3, s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len() as u64, out);
    out.extend_from_slice(b);
}

/// The signed data: DAG-CBOR, keys sorted by length, then bytewise.
pub fn data(spec: &Spec) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_head(5, if spec.unknown { 6 } else { 5 }, &mut out);
    cbor_text("TTL", &mut out);
    cbor_head(0, spec.ttl_ns, &mut out);
    if spec.unknown {
        cbor_text("Extra", &mut out);
        cbor_text("an unknown key", &mut out);
    }
    cbor_text("Value", &mut out);
    cbor_bytes(spec.value.as_bytes(), &mut out);
    cbor_text("Sequence", &mut out);
    cbor_head(0, spec.sequence, &mut out);
    cbor_text("Validity", &mut out);
    cbor_bytes(spec.validity.as_bytes(), &mut out);
    cbor_text("ValidityType", &mut out);
    cbor_head(0, 0, &mut out);
    out
}

/// The `IpnsEntry` protobuf, signed by `signer`.
pub fn record(spec: &Spec, signer: &Key) -> Result<Vec<u8>, Err> {
    let data = data(spec);
    let mut out = Vec::new();
    if spec.legacy {
        let value = spec.legacy_value.as_deref().unwrap_or(&spec.value);
        pb_bytes(1, value.as_bytes(), &mut out);
        let mut v1 = value.as_bytes().to_vec();
        v1.extend_from_slice(spec.validity.as_bytes());
        v1.extend_from_slice(b"EOL");
        pb_bytes(2, &signer.sign(&v1)?, &mut out);
        pb_varint(3, 0, &mut out);
        pb_bytes(4, spec.validity.as_bytes(), &mut out);
        pb_varint(5, spec.sequence, &mut out);
        pb_varint(6, spec.ttl_ns, &mut out);
    }
    if spec.pub_key || signer.kind == "rsa" {
        pb_bytes(7, &signer.proto, &mut out);
    }
    if spec.signature_v2 {
        let mut signed = b"ipns-signature:".to_vec();
        signed.extend_from_slice(&data);
        pb_bytes(8, &signer.sign(&signed)?, &mut out);
    }
    pb_bytes(9, &data, &mut out);
    if spec.unknown {
        pb_varint(15, 7, &mut out);
        pb_bytes(20, b"an unknown field", &mut out);
    }
    Ok(out)
}

/// freedom-ipfs's verdict on a record for a name.
pub fn native_verdict(name: &str, bytes: &[u8]) -> Value {
    match freedom_ipfs_namesys::verify_ipns_record(name, bytes) {
        Ok(r) => json!({
            "ok": {
                "value": r.value,
                "sequence": r.sequence,
                "validity": r.validity,
                "ttl_ns": r.ttl,
            }
        }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}
