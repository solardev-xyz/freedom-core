//! IPNS record checks: the RSA lies, other key types, weak Ed25519 keys and
//! the bounded decoders' limits (0009, IPNS and DNSLink, Bounded decoding).
//!
//! The honest records and the native reader's verdicts on them are in
//! dweb-verify.json; these are the design's cases around them. RSA
//! signatures whose key the `rsa` crate won't build (an exponent past its
//! bounds) are made with the textbook operation, `EM^d mod n`.

use super::{Err, bytes, fail, ok};
use crate::ipns::{self, Spec, data, name_of, pb_bytes, pb_varint};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rsa::BigUint;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA1_PREFIX: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const RSA_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn der_uint(v: &BigUint) -> Vec<u8> {
    let mut b = v.to_bytes_be();
    if b.first().is_some_and(|&x| x & 0x80 != 0) {
        b.insert(0, 0);
    }
    der(0x02, &b)
}

/// The PKIX `SubjectPublicKeyInfo` of an RSA key, in canonical DER.
fn spki(n: &BigUint, e: &BigUint) -> Vec<u8> {
    let mut alg = RSA_OID.to_vec();
    alg.extend_from_slice(&[0x05, 0x00]);
    let mut key = der_uint(n);
    key.extend_from_slice(&der_uint(e));
    let mut bits = vec![0x00];
    bits.extend_from_slice(&der(0x30, &key));
    let mut body = der(0x30, &alg);
    body.extend_from_slice(&der(0x03, &bits));
    der(0x30, &body)
}

fn proto(key_type: u64, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    pb_varint(1, key_type, &mut p);
    pb_bytes(2, data, &mut p);
    p
}

/// An `IpnsEntry` of only `pubKey`, `signatureV2` and `data`, in field order.
fn entry(pub_key: Option<&[u8]>, sig: Option<&[u8]>, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(k) = pub_key {
        pb_bytes(7, k, &mut out);
    }
    if let Some(s) = sig {
        pb_bytes(8, s, &mut out);
    }
    pb_bytes(9, data, &mut out);
    out
}

fn signed_message(data: &[u8]) -> Vec<u8> {
    let mut m = b"ipns-signature:".to_vec();
    m.extend_from_slice(data);
    m
}

/// EMSA-PKCS1-v1_5 (RFC 8017, 9.2) for a modulus of `k` bytes.
fn emsa(prefix: &[u8], digest: &[u8], k: usize) -> Result<Vec<u8>, Err> {
    let t = prefix.len() + digest.len();
    if k < t + 11 {
        return Err("modulus too short for the digest".into());
    }
    let mut em = vec![0x00, 0x01];
    em.resize(k - t - 1, 0xff);
    em.push(0x00);
    em.extend_from_slice(prefix);
    em.extend_from_slice(digest);
    Ok(em)
}

fn left_pad(b: Vec<u8>, k: usize) -> Vec<u8> {
    let mut out = vec![0u8; k.saturating_sub(b.len())];
    out.extend_from_slice(&b);
    out
}

struct Rsa {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    primes: Vec<BigUint>,
}

impl Rsa {
    fn new(label: &str, bits: usize) -> Result<Self, Err> {
        let mut rng = ChaCha20Rng::from_seed(Sha256::digest(label.as_bytes()).into());
        let sk = rsa::RsaPrivateKey::new_with_exp(&mut rng, bits, &BigUint::from(65_537u32))?;
        Ok(Self {
            n: sk.n().clone(),
            e: sk.e().clone(),
            d: sk.d().clone(),
            primes: sk.primes().to_vec(),
        })
    }

    fn k(&self) -> usize {
        self.n.bits().div_ceil(8)
    }

    fn proto(&self) -> Vec<u8> {
        proto(0, &spki(&self.n, &self.e))
    }

    fn raw_sign(&self, em: &[u8]) -> Vec<u8> {
        let m = BigUint::from_bytes_be(em);
        left_pad(m.modpow(&self.d, &self.n).to_bytes_be(), self.k())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Err> {
        Ok(self.raw_sign(&emsa(&SHA256_PREFIX, &Sha256::digest(msg), self.k())?))
    }

    /// The same primes with another public exponent, when one exists.
    fn with_exponent(&self, e: u64) -> Option<Self> {
        use rsa::BigUint as U;
        let one = U::from(1u32);
        let phi = self
            .primes
            .iter()
            .fold(one.clone(), |acc, p| acc * (p - &one));
        let e = U::from(e);
        let d = num_bigint_dig::ModInverse::mod_inverse(&e, &phi)?.to_biguint()?;
        Some(Self {
            n: self.n.clone(),
            e,
            d,
            primes: self.primes.clone(),
        })
    }
}

fn spec(value: &str, sequence: u64) -> Spec {
    Spec::v2(value, sequence)
}

const VALUE: &str = "/ipfs/bafybeiguwjmddvr4iiah6ekgvrovb5zfb6eg5c6loikxvxlxzlwea5dabm";

fn verdict(spec: &Spec) -> Value {
    ok(json!({
        "value": spec.value,
        "sequence": spec.sequence,
        "validity": spec.validity,
        "ttl_ns": spec.ttl_ns,
    }))
}

struct Records(Vec<Value>);

impl Records {
    fn push(
        &mut self,
        id: &str,
        note: &str,
        name: &str,
        record: &[u8],
        expect: Value,
        deviation: Option<&str>,
    ) {
        let native = ipns::native_verdict(name, record);
        let mut case = json!({
            "id": id,
            "note": note,
            "name": name,
            "record": bytes(record),
            "now": crate::swarm::CLOCK_UNIX,
            "expect": expect,
            "native": native,
        });
        if let Some(d) = deviation {
            case["deviation"] = json!(d);
        }
        self.0.push(case);
    }
}

/// A `data` map with one more key, whose value nests maps `depth` deep in
/// all, the record's own map counting as the first level.
fn nested_data(spec: &Spec, depth: usize) -> Vec<u8> {
    let plain = data(spec);
    // plain = map(5) …; rebuild as map(6) with "Extra" after "TTL".
    let mut out = vec![0xa6];
    let ttl_end = 1 + 4 + cbor_uint_len(spec.ttl_ns);
    out.extend_from_slice(&plain[1..ttl_end]);
    out.extend_from_slice(&[0x65, b'E', b'x', b't', b'r', b'a']);
    for _ in 0..depth.saturating_sub(2) {
        out.extend_from_slice(&[0xa1, 0x61, b'a']);
    }
    out.push(0xa0);
    out.extend_from_slice(&plain[ttl_end..]);
    out
}

fn cbor_uint_len(v: u64) -> usize {
    match v {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn rsa_records(r: &mut Records) -> Result<(), Err> {
    let a = Rsa::new("checks-rsa-a", 2048)?;
    let a_proto = a.proto();
    let a_name = name_of(&a_proto)?;
    // Hold the generator's DER to the rsa crate's own.
    let pk = rsa::RsaPublicKey::new(a.n.clone(), a.e.clone())?;
    if rsa::pkcs8::EncodePublicKey::to_public_key_der(&pk)?.as_bytes() != spki(&a.n, &a.e) {
        return Err("the generator's SPKI differs from the rsa crate's".into());
    }
    let s = spec(VALUE, 1);
    let d = data(&s);
    let good = entry(Some(&a_proto), Some(&a.sign(&signed_message(&d))?), &d);
    r.push(
        "rsa-2048",
        "an honest record of a 2,048-bit key, e = 65,537",
        &a_name,
        &good,
        verdict(&s),
        None,
    );

    let b = Rsa::new("checks-rsa-b", 2048)?;
    let rec = entry(Some(&b.proto()), Some(&b.sign(&signed_message(&d))?), &d);
    r.push(
        "rsa-key-not-name",
        "the record carries and is signed by another key than the one the name hashes",
        &a_name,
        &rec,
        fail("verification_failed"),
        None,
    );

    for (id, bits) in [("rsa-2040-bits", 2040usize), ("rsa-8193-bits", 8193)] {
        let k = Rsa::new(&format!("checks-{id}"), bits)?;
        if k.n.bits() != bits {
            return Err(format!("{id}: the modulus has {} bits", k.n.bits()).into());
        }
        let p = k.proto();
        let rec = entry(Some(&p), Some(&k.sign(&signed_message(&d))?), &d);
        r.push(
            id,
            &format!(
                "a {bits}-bit modulus, the signature valid for it: outside 2,048 to 8,192 bits"
            ),
            &name_of(&p)?,
            &rec,
            fail("verification_failed"),
            None,
        );
    }

    // e = 65,536: no valid signature exists; the record carries a's.
    let even = proto(0, &spki(&a.n, &BigUint::from(65_536u32)));
    let rec = entry(Some(&even), Some(&a.sign(&signed_message(&d))?), &d);
    r.push(
        "rsa-exponent-even",
        "a's modulus with the exponent 65,536",
        &name_of(&even)?,
        &rec,
        fail("verification_failed"),
        None,
    );

    // e = 1: the signature is the encoded message itself, and checks.
    let one = proto(0, &spki(&a.n, &BigUint::from(1u32)));
    let em = emsa(&SHA256_PREFIX, &Sha256::digest(signed_message(&d)), a.k())?;
    let rec = entry(Some(&one), Some(&em), &d);
    r.push("rsa-exponent-1", "the exponent 1, with the signature equal to the encoded message, which s^1 mod n reproduces", &name_of(&one)?, &rec, fail("verification_failed"), None);

    // e = 2^33 + 1, with a private exponent for it: a valid signature.
    let big = (1u64 << 33) + 1;
    let mut found = None;
    for i in 0..64 {
        let k = Rsa::new(&format!("checks-rsa-e33-{i}"), 2048)?;
        if let Some(k) = k.with_exponent(big) {
            found = Some(k);
            break;
        }
    }
    let k = found.ok_or("no key admits the exponent 2^33 + 1")?;
    let p = k.proto();
    let sig = k.sign(&signed_message(&d))?;
    let check = BigUint::from_bytes_be(&sig).modpow(&k.e, &k.n);
    if left_pad(check.to_bytes_be(), k.k())
        != emsa(&SHA256_PREFIX, &Sha256::digest(signed_message(&d)), k.k())?
    {
        return Err("the 2^33 + 1 signature doesn't check".into());
    }
    let rec = entry(Some(&p), Some(&sig), &d);
    r.push(
        "rsa-exponent-2^33+1",
        "the exponent 2^33 + 1, one past the bound, with a signature valid for it",
        &name_of(&p)?,
        &rec,
        fail("verification_failed"),
        None,
    );

    // A signature a byte short: one whose first byte is zero, without it.
    let mut short = None;
    for seq in 2..4096u64 {
        let s2 = spec(VALUE, seq);
        let d2 = data(&s2);
        let sig = a.sign(&signed_message(&d2))?;
        if sig[0] == 0 {
            short = Some((d2, sig));
            break;
        }
    }
    let (d2, sig) = short.ok_or("no signature with a leading zero")?;
    let rec = entry(Some(&a_proto), Some(&sig[1..]), &d2);
    r.push("rsa-signature-short", "a valid signature whose first byte is zero, sent without it: the same integer, a byte shorter than the modulus", &a_name, &rec, fail("verification_failed"), None);

    let rec = entry(
        Some(&a_proto),
        Some(&left_pad(a.n.to_bytes_be(), a.k())),
        &d,
    );
    r.push(
        "rsa-signature-modulus",
        "a signature equal to the modulus",
        &a_name,
        &rec,
        fail("verification_failed"),
        None,
    );

    let sha1 = {
        use sha1::Digest as _;
        sha1::Sha1::digest(signed_message(&d)).to_vec()
    };
    let rec = entry(
        Some(&a_proto),
        Some(&a.raw_sign(&emsa(&SHA1_PREFIX, &sha1, a.k())?)),
        &d,
    );
    r.push(
        "rsa-sha1",
        "PKCS#1 v1.5 over the right message, with SHA-1",
        &a_name,
        &rec,
        fail("verification_failed"),
        None,
    );

    let rec = entry(None, Some(&a.sign(&signed_message(&d))?), &d);
    r.push(
        "rsa-no-pubkey",
        "a sha2-256 name, and a record without pubKey",
        &a_name,
        &rec,
        fail("verification_failed"),
        None,
    );

    // DER lengths past the bytes remaining.
    let canon = spki(&a.n, &a.e);
    let mut past = canon.clone();
    // The outer SEQUENCE is 30 82 hi lo: claim ten more bytes.
    let len = u16::from_be_bytes([past[2], past[3]]) + 10;
    past[2..4].copy_from_slice(&len.to_be_bytes());
    let p = proto(0, &past);
    let rec = entry(Some(&p), Some(&a.sign(&signed_message(&d))?), &d);
    r.push(
        "rsa-der-length-past-end",
        "the key's outer SEQUENCE claims ten bytes more than it has",
        &name_of(&p)?,
        &rec,
        fail("verification_failed"),
        None,
    );
    let at = canon
        .windows(4)
        .position(|w| w[0] == 0x02 && w[1] == 0x82 && u16::from_be_bytes([w[2], w[3]]) == 257)
        .ok_or("the modulus INTEGER")?;
    let mut huge = canon[..at].to_vec();
    huge.extend_from_slice(&[0x02, 0x84, 0x7f, 0xff, 0xff, 0xff]);
    huge.extend_from_slice(&canon[at + 4..]);
    let p = proto(0, &huge);
    let rec = entry(Some(&p), Some(&a.sign(&signed_message(&d))?), &d);
    r.push(
        "rsa-modulus-length-huge",
        "the modulus INTEGER's length field claims 2^31 − 1 bytes",
        &name_of(&p)?,
        &rec,
        fail("verification_failed"),
        None,
    );
    Ok(())
}

/// P-256's base point, uncompressed: a valid ECDSA public key.
const P256_G: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

fn other_keys(r: &mut Records) -> Result<(), Err> {
    let s = spec(VALUE, 1);
    let d = data(&s);
    // ECDSA: id-ecPublicKey, prime256v1.
    let mut alg = vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    alg.extend_from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    let mut bits = vec![0x00];
    bits.extend_from_slice(&P256_G);
    let mut body = der(0x30, &alg);
    body.extend_from_slice(&der(0x03, &bits));
    let p = proto(3, &der(0x30, &body));
    let rec = entry(
        Some(&p),
        Some(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
        &d,
    );
    r.push(
        "ecdsa-key",
        "a sha2-256 name whose record's key is ECDSA (P-256)",
        &name_of(&p)?,
        &rec,
        fail("unverifiable"),
        None,
    );

    // Ed25519's identity point, a small-order key, and the signature
    // (R = the identity, S = 0), which checks for any message under the
    // cofactorless equation the non-strict verifier uses.
    let mut weak = [0u8; 32];
    weak[0] = 0x01;
    let p = proto(1, &weak);
    let mut sig = weak.to_vec();
    sig.extend_from_slice(&[0u8; 32]);
    let rec = entry(None, Some(&sig), &d);
    r.push("ed25519-small-order-key", "an inlined Ed25519 key that is the identity point, with R the identity and S = 0: valid under non-strict verification (decided: a weak key weakens only its owner's own name)", &name_of(&p)?, &rec, verdict(&s), None);

    let ed = crate::ipns::Key::ed25519("checks-ed25519");
    let name = ed.name()?;
    let good = ed.sign(&signed_message(&d))?;
    let rec = entry(None, Some(&good), &d);
    r.push(
        "ed25519",
        "an honest V2-only record",
        &name,
        &rec,
        verdict(&s),
        None,
    );
    // S + L: the same S modulo L, not canonical.
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut s_plus = good.clone();
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(s_plus[32 + i]) + u16::from(l[i]) + carry;
        s_plus[32 + i] = v as u8;
        carry = v >> 8;
    }
    let rec = entry(None, Some(&s_plus), &d);
    r.push(
        "ed25519-s-not-canonical",
        "the honest signature with L added to S",
        &name,
        &rec,
        fail("verification_failed"),
        None,
    );

    for (id, depth, expect, dev) in [
        ("cbor-depth-8", 8usize, verdict(&s), None),
        (
            "cbor-depth-9",
            9,
            fail("unverifiable"),
            Some("decoder-caps"),
        ),
    ] {
        let dd = nested_data(&s, depth);
        let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
        r.push(id, &format!("signed data with an unknown key whose value nests maps {depth} levels deep, the record's map the first"), &name, &rec, expect, dev);
    }
    let mut dd = data(&s);
    // "Value"'s byte string: claim more bytes than remain.
    let at = dd
        .windows(6)
        .position(|w| w == [0x65, b'V', b'a', b'l', b'u', b'e'])
        .ok_or("Value key")?
        + 6;
    dd[at] = 0x59;
    dd.insert(at + 1, 0xff);
    dd.insert(at + 2, 0xff);
    let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
    r.push(
        "cbor-length-past-end",
        "signed data whose Value claims 65,535 bytes",
        &name,
        &rec,
        fail("verification_failed"),
        None,
    );

    let mut type1 = spec(VALUE, 1);
    type1.validity = ipns::VALID_EOL.to_string();
    let mut dd = data(&type1);
    let n = dd.len();
    dd[n - 1] = 0x01;
    let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
    r.push(
        "validity-type-1",
        "ValidityType 1: only EOL (0) is defined",
        &name,
        &rec,
        fail("verification_failed"),
        None,
    );

    let bad = spec("/http/example.com", 1);
    let dd = data(&bad);
    let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
    r.push(
        "value-not-a-path",
        "a value that starts neither /ipfs/ nor /ipns/",
        &name,
        &rec,
        fail("verification_failed"),
        None,
    );

    let mut big = entry(None, Some(&good), &d);
    pb_bytes(20, &vec![0u8; 10 * 1024], &mut big);
    r.push(
        "over-10-kib",
        "the honest record with an unknown field past 10 KiB",
        &name,
        &big,
        fail("verification_failed"),
        None,
    );
    Ok(())
}

pub fn build() -> Result<Value, Err> {
    let mut r = Records(Vec::new());
    rsa_records(&mut r)?;
    other_keys(&mut r)?;
    Ok(json!({ "records": r.0 }))
}
