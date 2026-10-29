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

struct Records(Vec<Value>, Vec<String>);

impl Records {
    /// A case whose native verdict is checked by its caller.
    fn push_unchecked(&mut self, id: &str, note: &str, name: &str, record: &[u8], expect: Value) {
        let before = self.1.len();
        self.push(id, note, name, record, expect, None);
        self.1.truncate(before);
    }

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
        // The native verdict agrees with the design's unless a deviation is named.
        if deviation.is_none() && native.get("ok").is_some() != expect.get("ok").is_some() {
            self.1
                .push(format!("record case {id}: freedom-ipfs says {native}"));
        }
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

    // Canonical DER (0009, Bounded decoding): each key below is a's, its
    // SPKI encoded one other way, the name the hash of the bytes as they
    // arrive, and the signature valid for a's modulus and exponent. Only
    // the encoding is outside the rules.
    let n_int = der_uint(&a.n);
    let e_int = der_uint(&a.e);
    let null_alg = [RSA_OID.to_vec(), vec![0x05, 0x00]].concat();
    let rsa_key = |n: &[u8], e: &[u8], extra: &[u8]| der(0x30, &[n, e, extra].concat());
    let bit_string = |unused: u8, inner: &[u8]| der(0x03, &[&[unused][..], inner].concat());
    let spki_of = |alg: &[u8], key: &[u8]| der(0x30, &[der(0x30, alg), key.to_vec()].concat());
    if spki_of(&null_alg, &bit_string(0, &rsa_key(&n_int, &e_int, &[]))) != canon {
        return Err("the DER cases' SPKI differs from the canonical one".into());
    }
    let n_bytes = a.n.to_bytes_be();
    let honest_key = rsa_key(&n_int, &e_int, &[]);
    let mut indefinite = vec![0x30, 0x80];
    indefinite.extend_from_slice(&canon[4..]);
    indefinite.extend_from_slice(&[0x00, 0x00]);
    let mut long_alg = vec![0x30, 0x81, null_alg.len() as u8];
    long_alg.extend_from_slice(&null_alg);
    let pss = [
        vec![
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
        ],
        vec![0x05, 0x00],
    ]
    .concat();
    for (id, note, key) in [
        (
            "rsa-der-modulus-leading-zero",
            "the modulus INTEGER with a second leading zero byte: not minimal",
            spki_of(
                &null_alg,
                &bit_string(
                    0,
                    &rsa_key(
                        &der(0x02, &[&[0u8, 0u8][..], &n_bytes].concat()),
                        &e_int,
                        &[],
                    ),
                ),
            ),
        ),
        (
            "rsa-der-modulus-negative",
            "the modulus INTEGER without its zero sign byte: a negative integer",
            spki_of(
                &null_alg,
                &bit_string(0, &rsa_key(&der(0x02, &n_bytes), &e_int, &[])),
            ),
        ),
        (
            "rsa-der-exponent-leading-zero",
            "the exponent as 00 01 00 01: not minimal",
            spki_of(
                &null_alg,
                &bit_string(
                    0,
                    &rsa_key(&n_int, &der(0x02, &[0x00, 0x01, 0x00, 0x01]), &[]),
                ),
            ),
        ),
        (
            "rsa-der-extra-integer",
            "a third INTEGER in the RSAPublicKey",
            spki_of(
                &null_alg,
                &bit_string(0, &rsa_key(&n_int, &e_int, &der(0x02, &[0x00]))),
            ),
        ),
        (
            "rsa-der-indefinite-length",
            "the outer SEQUENCE with an indefinite length and end-of-contents",
            indefinite.clone(),
        ),
        (
            "rsa-der-long-form-short-length",
            "the AlgorithmIdentifier's length, 13, in long form",
            der(
                0x30,
                &[long_alg.clone(), bit_string(0, &honest_key)].concat(),
            ),
        ),
        (
            "rsa-der-parameters-absent",
            "the AlgorithmIdentifier without its NULL parameters",
            spki_of(&RSA_OID, &bit_string(0, &honest_key)),
        ),
        (
            "rsa-der-other-algorithm",
            "the AlgorithmIdentifier of RSASSA-PSS (1.2.840.113549.1.1.10)",
            spki_of(&pss, &bit_string(0, &honest_key)),
        ),
        (
            "rsa-der-unused-bits",
            "the BIT STRING declaring one unused bit",
            spki_of(&null_alg, &bit_string(1, &honest_key)),
        ),
        (
            "rsa-der-octet-string",
            "the RSAPublicKey in an OCTET STRING, not a BIT STRING",
            spki_of(&null_alg, &der(0x04, &honest_key)),
        ),
        (
            "rsa-der-trailing-byte",
            "a zero byte after the SPKI",
            [canon.clone(), vec![0x00]].concat(),
        ),
        (
            "rsa-der-pkcs1",
            "the bare PKCS#1 RSAPublicKey, without the SPKI around it",
            honest_key.clone(),
        ),
    ] {
        let p = proto(0, &key);
        let rec = entry(Some(&p), Some(&a.sign(&signed_message(&d))?), &d);
        r.push(
            id,
            note,
            &name_of(&p)?,
            &rec,
            fail("verification_failed"),
            None,
        );
    }
    Ok(())
}

fn other_keys(r: &mut Records) -> Result<(), Err> {
    let s = spec(VALUE, 1);
    let d = data(&s);
    // ECDSA: id-ecPublicKey, prime256v1, a seeded key, and a valid
    // signature (DER, over SHA-256, as libp2p signs): only the key's type
    // is outside the rules.
    let sk = p256::ecdsa::SigningKey::from_bytes(&Sha256::digest(b"checks-ecdsa"))?;
    let point = sk.verifying_key().to_encoded_point(false);
    let mut alg = vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    alg.extend_from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    let mut bits = vec![0x00];
    bits.extend_from_slice(point.as_bytes());
    let mut body = der(0x30, &alg);
    body.extend_from_slice(&der(0x03, &bits));
    let p = proto(3, &der(0x30, &body));
    let sig: p256::ecdsa::Signature =
        p256::ecdsa::signature::Signer::sign(&sk, &signed_message(&d));
    p256::ecdsa::signature::Verifier::verify(sk.verifying_key(), &signed_message(&d), &sig)?;
    let rec = entry(Some(&p), Some(sig.to_der().as_bytes()), &d);
    let name = name_of(&p)?;
    // This generator's libp2p-identity has ECDSA (through Ant's libp2p),
    // so its verdict shows the record otherwise valid; freedom-ipfsd's
    // can't decode the key.
    if ipns::native_verdict(&name, &rec) != verdict(&s) {
        return Err("the ECDSA record isn't otherwise valid".into());
    }
    r.push_unchecked(
        "ecdsa-key",
        "a sha2-256 name whose record's key is ECDSA (P-256), validly signed: only the key's type differs from an RSA record",
        &name,
        &rec,
        fail("unverifiable"),
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

    // Bounded CBOR (0009, Bounded decoding): the honest signed data with
    // one change the reader refuses, each validly signed. The signer made
    // it, so once its signature passes it is unverifiable, not a lie.
    use crate::ipns::{cbor_bytes, cbor_head, cbor_text};
    let kv_uint = |k: &str, v: u64| {
        let mut o = Vec::new();
        cbor_text(k, &mut o);
        cbor_head(0, v, &mut o);
        o
    };
    let kv_bytes = |k: &str, v: &[u8]| {
        let mut o = Vec::new();
        cbor_text(k, &mut o);
        cbor_bytes(v, &mut o);
        o
    };
    let ttl = kv_uint("TTL", s.ttl_ns);
    let value = kv_bytes("Value", s.value.as_bytes());
    let rest = [
        kv_uint("Sequence", s.sequence),
        kv_bytes("Validity", s.validity.as_bytes()),
        kv_uint("ValidityType", 0),
    ]
    .concat();
    if [vec![0xa5], ttl.clone(), value.clone(), rest.clone()].concat() != data(&s) {
        return Err("the CBOR cases' data differs from the honest one".into());
    }
    let mut extra_key = Vec::new();
    cbor_text("Extra", &mut extra_key);
    let cid = cid::Cid::try_from(&VALUE[6..])?;
    let mut tag42 = vec![0xd8, 0x2a];
    cbor_bytes(&[&[0u8][..], &cid.to_bytes()].concat(), &mut tag42);
    let mut tag42_no_prefix = vec![0xd8, 0x2a];
    cbor_bytes(&cid.to_bytes(), &mut tag42_no_prefix);
    let mut value_key = Vec::new();
    cbor_text("Value", &mut value_key);
    let mut indefinite_value = value_key.clone();
    indefinite_value.push(0x5f);
    cbor_bytes(s.value.as_bytes(), &mut indefinite_value);
    indefinite_value.push(0xff);
    let mut tagged_value = value_key.clone();
    tagged_value.extend_from_slice(&[0xd8, 0x2a]);
    cbor_bytes(s.value.as_bytes(), &mut tagged_value);
    let mut ttl_key = Vec::new();
    cbor_text("TTL", &mut ttl_key);
    let mut indefinite_key = vec![0x7f];
    indefinite_key.extend_from_slice(&ttl_key);
    indefinite_key.push(0xff);
    cbor_head(0, s.ttl_ns, &mut indefinite_key);
    for (id, note, dd) in [
        (
            "cbor-indefinite-map",
            "the data's map with an indefinite length",
            [
                vec![0xbf],
                ttl.clone(),
                value.clone(),
                rest.clone(),
                vec![0xff],
            ]
            .concat(),
        ),
        (
            "cbor-indefinite-bytes",
            "Value as an indefinite-length byte string",
            [
                vec![0xa5],
                ttl.clone(),
                indefinite_value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
        (
            "cbor-indefinite-key",
            "the key TTL as an indefinite-length text string",
            [
                vec![0xa5],
                indefinite_key.clone(),
                value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
        (
            "cbor-integer-key",
            "an entry whose key is the integer 1",
            [
                vec![0xa6, 0x01, 0x01],
                ttl.clone(),
                value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
        (
            "cbor-integer-key-nested",
            "an unknown key whose value is a map with an integer key",
            [
                vec![0xa6],
                ttl.clone(),
                extra_key.clone(),
                vec![0xa1, 0x01, 0x01],
                value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
        (
            "cbor-duplicate-key",
            "TTL twice, with the same value",
            [
                vec![0xa6],
                ttl.clone(),
                ttl.clone(),
                value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
        (
            "cbor-tag-42-not-bytes",
            "an unknown key whose value is tag 42 over an integer: not a CID",
            [
                vec![0xa6],
                ttl.clone(),
                extra_key.clone(),
                vec![0xd8, 0x2a, 0x01],
                value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
        (
            "cbor-tag-42-no-prefix",
            "an unknown key whose value is tag 42 over a CID's bytes without the 0x00 prefix",
            [
                vec![0xa6],
                ttl.clone(),
                extra_key.clone(),
                tag42_no_prefix.clone(),
                value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
        (
            "cbor-tag-42-not-a-cid",
            "an unknown key whose value is tag 42 over 0x00 and bytes that aren't a CID",
            [
                vec![0xa6],
                ttl.clone(),
                extra_key.clone(),
                vec![0xd8, 0x2a, 0x44, 0x00, 0x07, 0x07, 0x07],
                value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
        (
            "cbor-tag-42-value",
            "Value's bytes under tag 42",
            [vec![0xa5], ttl.clone(), tagged_value.clone(), rest.clone()].concat(),
        ),
        (
            "cbor-other-tag",
            "an unknown key whose value is tag 1 (an epoch time): DAG-CBOR has only tag 42",
            [
                vec![0xa6],
                ttl.clone(),
                extra_key.clone(),
                vec![0xc1, 0x00],
                value.clone(),
                rest.clone(),
            ]
            .concat(),
        ),
    ] {
        let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
        // The native reader takes an indefinite-length key (dag-cbor-strict).
        let dev = (id == "cbor-indefinite-key").then_some("dag-cbor-strict");
        r.push(id, note, &name, &rec, fail("unverifiable"), dev);
    }
    // The strict profile, at every level, each validly signed.
    let mut seq_key = Vec::new();
    cbor_text("Sequence", &mut seq_key);
    let validity = kv_bytes("Validity", s.validity.as_bytes());
    let sequence = kv_uint("Sequence", s.sequence);
    let validity_type = kv_uint("ValidityType", 0);
    let mut ttl_long_key = vec![0x78, 0x03];
    ttl_long_key.extend_from_slice(b"TTL");
    cbor_head(0, s.ttl_ns, &mut ttl_long_key);
    let mut non_minimal_cid = vec![0xd8, 0x2a];
    let mut cid_bytes = vec![0x00, 0x81, 0x00];
    cid_bytes.extend_from_slice(&cid.to_bytes()[1..]);
    cbor_bytes(&cid_bytes, &mut non_minimal_cid);
    let extra = |v: &[u8]| {
        [
            vec![0xa6],
            ttl.clone(),
            extra_key.clone(),
            v.to_vec(),
            value.clone(),
            rest.clone(),
        ]
        .concat()
    };
    for (id, note, dd, dev) in [
        (
            "cbor-key-order",
            "Validity before Sequence: not canonical order",
            [
                vec![0xa5],
                ttl.clone(),
                value.clone(),
                validity.clone(),
                sequence.clone(),
                validity_type.clone(),
            ]
            .concat(),
            true,
        ),
        (
            "cbor-key-order-nested",
            "an unknown key whose map has b before a",
            extra(&[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x01]),
            true,
        ),
        (
            "cbor-duplicate-key-nested",
            "an unknown key whose map has a twice",
            extra(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x01]),
            true,
        ),
        (
            "cbor-integer-not-minimal",
            "Sequence 1 in two bytes (0x18 0x01)",
            [
                vec![0xa5],
                ttl.clone(),
                value.clone(),
                seq_key.clone(),
                vec![0x18, 0x01],
                validity.clone(),
                validity_type.clone(),
            ]
            .concat(),
            true,
        ),
        (
            "cbor-length-not-minimal",
            "the key TTL with its length in two bytes (0x78 0x03)",
            [
                vec![0xa5],
                ttl_long_key.clone(),
                value.clone(),
                rest.clone(),
            ]
            .concat(),
            true,
        ),
        (
            "cbor-float-nan",
            "an unknown key whose value is a NaN",
            extra(&[0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0]),
            true,
        ),
        (
            "cbor-float-infinity",
            "an unknown key whose value is infinity",
            extra(&[0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0]),
            true,
        ),
        (
            "cbor-float-negative-zero",
            "an unknown key whose value is negative zero, which DAG-CBOR's strictness refuses",
            extra(&[0xfb, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            true,
        ),
        (
            "cbor-float-32",
            "an unknown key whose value is a 32-bit float",
            extra(&[0xfa, 0x3f, 0xc0, 0, 0]),
            true,
        ),
        (
            "cbor-tag-42-empty",
            "an unknown key whose value is tag 42 over an empty byte string",
            extra(&[0xd8, 0x2a, 0x40]),
            true,
        ),
        (
            "cbor-tag-42-prefix-only",
            "an unknown key whose value is tag 42 over 0x00 alone",
            extra(&[0xd8, 0x2a, 0x41, 0x00]),
            true,
        ),
        (
            "cbor-tag-42-cid-not-minimal",
            "an unknown key whose value is a CID whose version is the varint 0x81 0x00",
            extra(&non_minimal_cid),
            true,
        ),
    ] {
        let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
        let native_ok = ipns::native_verdict(&name, &rec).get("ok").is_some();
        let dev = (dev && native_ok).then_some("dag-cbor-strict");
        r.push(id, note, &name, &rec, fail("unverifiable"), dev);
    }
    let dd = extra(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]);
    let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
    r.push(
        "cbor-float-zero",
        "an unknown key whose value is the 64-bit float 0 (positive): read",
        &name,
        &rec,
        verdict(&s),
        None,
    );
    let dd = extra(&[0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]);
    let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
    r.push(
        "cbor-float-finite",
        "an unknown key whose value is the 64-bit float 1.5: read",
        &name,
        &rec,
        verdict(&s),
        None,
    );
    // A CID wherever DAG-CBOR allows a link: under an unknown key, skipped.
    let dd = [
        vec![0xa6],
        ttl.clone(),
        extra_key.clone(),
        tag42.clone(),
        value.clone(),
        rest.clone(),
    ]
    .concat();
    let rec = entry(None, Some(&ed.sign(&signed_message(&dd))?), &dd);
    r.push("cbor-tag-42-unknown-key", "an unknown key whose value is a CID (tag 42): a link where DAG-CBOR allows one, skipped as the IPNS specification skips unknown keys", &name, &rec, verdict(&s), None);
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
        "signed data whose Value claims 65,535 bytes: validly signed, so unverifiable",
        &name,
        &rec,
        fail("unverifiable"),
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
    let mut r = Records(Vec::new(), Vec::new());
    rsa_records(&mut r)?;
    other_keys(&mut r)?;
    if !r.1.is_empty() {
        return Err(r.1.join("; ").into());
    }
    Ok(json!({ "records": r.0 }))
}
