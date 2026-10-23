#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use hpke::aead::AeadCtxR;
use rand_core::TryRng;

/// RFC 9180's test vector for this suite in base mode: the one entry of the
/// CFRG's `test-vectors.json` (cfrg/draft-irtf-cfrg-hpke at
/// 5f503c564da00b0687b3de75f1dfbdfc4079ad31, sha256 61fc662f…3ede6, the file
/// the RFC's appendix points to and hpke 0.14.1 ships) with `mode` 0,
/// `kem_id` 0x20, `kdf_id` 0x1 and `aead_id` 0x2. RFC 9180's appendix
/// prints no vector for AES-256-GCM with X25519; the file has it.
const VECTORS: &str = include_str!("../testdata/rfc9180-base-x25519-sha256-aes256gcm.json");

#[derive(serde::Deserialize)]
struct Vector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename = "ikmR")]
    ikm_r: String,
    #[serde(rename = "ikmE")]
    ikm_e: String,
    #[serde(rename = "skRm")]
    sk_rm: String,
    #[serde(rename = "pkRm")]
    pk_rm: String,
    #[serde(rename = "skEm")]
    sk_em: String,
    #[serde(rename = "pkEm")]
    pk_em: String,
    enc: String,
    encryptions: Vec<Encryption>,
    exports: Vec<Export>,
}

#[derive(serde::Deserialize)]
struct Encryption {
    aad: String,
    ct: String,
    pt: String,
}

#[derive(serde::Deserialize)]
struct Export {
    exporter_context: String,
    #[serde(rename = "L")]
    len: usize,
    exported_value: String,
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn vector() -> Vector {
    let mut all: Vec<Vector> = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(all.len(), 1);
    let v = all.remove(0);
    assert_eq!(
        (v.mode, v.kem_id, v.kdf_id, v.aead_id),
        (0, 0x20, 0x1, 0x2),
        "the vector is this suite's, in base mode"
    );
    v
}

/// Gives exactly the bytes it holds, then fails.
struct Bytes(Vec<u8>);

impl TryRng for Bytes {
    type Error = RngError;
    fn try_next_u32(&mut self) -> Result<u32, RngError> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, RngError> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        if dst.len() > self.0.len() {
            return Err(RngError);
        }
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Bytes {}

struct Failing;

impl TryRng for Failing {
    type Error = RngError;
    fn try_next_u32(&mut self) -> Result<u32, RngError> {
        Err(RngError)
    }
    fn try_next_u64(&mut self) -> Result<u64, RngError> {
        Err(RngError)
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RngError> {
        Err(RngError)
    }
}

impl rand_core::TryCryptoRng for Failing {}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

#[test]
fn the_suite_reproduces_rfc_9180s_vector_key_pairs() {
    let v = vector();
    let (sk_r, pk_r) = <Kem as hpke::Kem>::derive_keypair(&unhex(&v.ikm_r));
    assert_eq!(sk_r.to_bytes().to_vec(), unhex(&v.sk_rm));
    assert_eq!(pk_r.to_bytes().to_vec(), unhex(&v.pk_rm));
    let (sk_e, pk_e) = <Kem as hpke::Kem>::derive_keypair(&unhex(&v.ikm_e));
    assert_eq!(sk_e.to_bytes().to_vec(), unhex(&v.sk_em));
    assert_eq!(pk_e.to_bytes().to_vec(), unhex(&v.pk_em));
    // The recipient key the service makes from 32 bytes of keying
    // material is DeriveKeyPair's.
    let recipient = RecipientKey::from_ikm(&array(&unhex(&v.ikm_r)));
    assert_eq!(recipient.public_key().to_vec(), unhex(&v.pk_rm));
    let generated = RecipientKey::generate(&mut Bytes(unhex(&v.ikm_r))).unwrap();
    assert_eq!(generated.public_key().to_vec(), unhex(&v.pk_rm));
}

/// Every encryption and export of the vector, through the suite's context:
/// the sender's from its ephemeral keying material, the receiver's from
/// its private key.
#[test]
fn the_suite_reproduces_every_encryption_and_export_of_rfc_9180s_vector() {
    let v = vector();
    let info = unhex(&v.info);
    let pk_r = <Kem as hpke::Kem>::PublicKey::from_bytes(&unhex(&v.pk_rm)).unwrap();
    let mut eph = Owned(array(&unhex(&v.ikm_e)));
    let (enc, mut sender) =
        hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(&OpModeS::Base, &pk_r, &info, &mut eph.rng())
            .unwrap();
    assert_eq!(enc.to_bytes().to_vec(), unhex(&v.enc));
    let sk_r = <Kem as hpke::Kem>::PrivateKey::from_bytes(&unhex(&v.sk_rm)).unwrap();
    let mut receiver: AeadCtxR<Aead, Kdf, Kem> =
        hpke::setup_receiver(&OpModeR::Base, &sk_r, &enc, &info).unwrap();
    assert_eq!(v.encryptions.len(), 257);
    for e in &v.encryptions {
        let pt = unhex(&e.pt);
        let aad = unhex(&e.aad);
        let mut buf = pt.clone();
        let tag = sender
            .seal_inout_detached(InOutBuf::from(buf.as_mut_slice()), &aad)
            .unwrap();
        let mut ct = buf.clone();
        ct.extend_from_slice(&tag.to_bytes());
        assert_eq!(ct, unhex(&e.ct));
        receiver
            .open_inout_detached(InOutBuf::from(buf.as_mut_slice()), &aad, &tag)
            .unwrap();
        assert_eq!(buf, pt);
    }
    for x in &v.exports {
        let mut out = vec![0u8; x.len];
        sender
            .export(&unhex(&x.exporter_context), &mut out)
            .unwrap();
        assert_eq!(out, unhex(&x.exported_value));
    }
}

/// The single-shot seal [`seal`] makes is the vector's first encryption,
/// given the vector's ephemeral keying material: same `enc`, same
/// ciphertext, under the vector's `info` and `aad`.
#[test]
fn a_single_shot_seal_is_the_vectors_first_encryption() {
    let v = vector();
    let pk_r = <Kem as hpke::Kem>::PublicKey::from_bytes(&unhex(&v.pk_rm)).unwrap();
    let first = &v.encryptions[0];
    let mut buf = unhex(&first.pt);
    let mut eph = Owned(array(&unhex(&v.ikm_e)));
    let (enc, tag) = hpke::single_shot_seal_inout_detached_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk_r,
        &unhex(&v.info),
        InOutBuf::from(buf.as_mut_slice()),
        &unhex(&first.aad),
        &mut eph.rng(),
    )
    .unwrap();
    assert_eq!(enc.to_bytes().to_vec(), unhex(&v.enc));
    buf.extend_from_slice(&tag.to_bytes());
    assert_eq!(buf, unhex(&first.ct));
}

/// [`seal`] is the suite with [`INFO`] and an empty `aad`: a key sealed with
/// the vector's ephemeral material opens with the vector's private key
/// through hpke directly, and only under `INFO`.
#[test]
fn seal_binds_info_and_an_empty_aad() {
    let v = vector();
    let key = [7u8; KEY_LEN];
    let sealed = seal(&array(&unhex(&v.pk_rm)), &key, &mut Bytes(unhex(&v.ikm_e))).unwrap();
    assert_eq!(sealed.enc.to_vec(), unhex(&v.enc));
    let sk_r = <Kem as hpke::Kem>::PrivateKey::from_bytes(&unhex(&v.sk_rm)).unwrap();
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&sealed.enc).unwrap();
    let tag = AeadTag::<Aead>::from_bytes(&sealed.ciphertext[KEY_LEN..]).unwrap();
    let open = |info: &[u8], aad: &[u8]| {
        let mut buf = sealed.ciphertext[..KEY_LEN].to_vec();
        hpke::single_shot_open_inout_detached::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &sk_r,
            &enc,
            info,
            InOutBuf::from(buf.as_mut_slice()),
            aad,
            &tag,
        )
        .map(|()| buf)
    };
    assert_eq!(open(INFO, &[]).unwrap(), key);
    assert!(open(b"freedom-radicle-node-key/2", &[]).is_err());
    assert!(open(INFO, b"x").is_err());
}

#[test]
fn a_sealed_key_opens_once_with_its_recipient() {
    let recipient = RecipientKey::generate(&mut Bytes(vec![1; 32])).unwrap();
    let key = [42u8; KEY_LEN];
    let sealed = seal(&recipient.public_key(), &key, &mut Bytes(vec![2; 32])).unwrap();
    assert_eq!(sealed.enc.len(), ENC_LEN);
    assert_eq!(sealed.ciphertext.len(), CIPHERTEXT_LEN);
    assert_ne!(&sealed.ciphertext[..KEY_LEN], &key[..]);
    let opened = recipient.open(&sealed.enc, &sealed.ciphertext).unwrap();
    assert_eq!(*opened, key);
}

#[test]
fn another_starts_key_cant_open_it() {
    let earlier = RecipientKey::generate(&mut Bytes(vec![1; 32])).unwrap();
    let now = RecipientKey::generate(&mut Bytes(vec![3; 32])).unwrap();
    let sealed = seal(
        &earlier.public_key(),
        &[9; KEY_LEN],
        &mut Bytes(vec![2; 32]),
    )
    .unwrap();
    assert_eq!(now.open(&sealed.enc, &sealed.ciphertext), Err(OpenError));
}

#[test]
fn any_tampering_fails_to_open() {
    let key = [5u8; KEY_LEN];
    let fresh = || RecipientKey::generate(&mut Bytes(vec![1; 32])).unwrap();
    let sealed = seal(&fresh().public_key(), &key, &mut Bytes(vec![2; 32])).unwrap();
    for i in 0..CIPHERTEXT_LEN {
        let mut ct = sealed.ciphertext;
        ct[i] ^= 1;
        assert_eq!(fresh().open(&sealed.enc, &ct), Err(OpenError), "byte {i}");
    }
    for i in 0..ENC_LEN {
        let mut enc = sealed.enc;
        enc[i] ^= 1;
        assert_eq!(
            fresh().open(&enc, &sealed.ciphertext),
            Err(OpenError),
            "enc byte {i}"
        );
    }
    // Lengths other than 32 and 48: refused before anything opens.
    assert_eq!(
        fresh().open(&sealed.enc[..31], &sealed.ciphertext),
        Err(OpenError)
    );
    assert_eq!(
        fresh().open(&sealed.enc, &sealed.ciphertext[..47]),
        Err(OpenError)
    );
    let mut longer = sealed.ciphertext.to_vec();
    longer.push(0);
    assert_eq!(fresh().open(&sealed.enc, &longer), Err(OpenError));
    assert_eq!(fresh().open(&[], &[]), Err(OpenError));
    // Untouched, it opens.
    assert_eq!(*fresh().open(&sealed.enc, &sealed.ciphertext).unwrap(), key);
}

/// X25519's low-order points (RFC 7748 §5 and the usual list of
/// non-canonical encodings): each gives the all-zero shared secret, which
/// RFC 9180 §7.1.4 makes an error, so nothing is sealed to them.
#[test]
fn low_order_recipients_are_refused() {
    let low_order: [&str; 7] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    for point in low_order {
        assert_eq!(
            seal(
                &array(&unhex(point)),
                &[1; KEY_LEN],
                &mut Bytes(vec![2; 32])
            ),
            Err(SealError::InvalidRecipient),
            "{point}"
        );
    }
}

#[test]
fn rng_failure_is_an_error() {
    let recipient = RecipientKey::generate(&mut Bytes(vec![1; 32])).unwrap();
    assert_eq!(
        seal(&recipient.public_key(), &[1; KEY_LEN], &mut Failing),
        Err(SealError::Rng)
    );
    assert_eq!(
        seal(
            &recipient.public_key(),
            &[1; KEY_LEN],
            &mut Bytes(vec![2; 31])
        ),
        Err(SealError::Rng)
    );
    assert_eq!(RecipientKey::generate(&mut Failing).unwrap_err(), RngError);
}

/// The KEM draws exactly one key pair's keying material from [`seal`]'s
/// fixed source; asked for more, the seal is refused.
#[test]
fn the_fixed_source_refuses_an_overrun() {
    let ikm = [3u8; IKM_LEN];
    let mut fixed = FixedRng::new(&ikm);
    let mut first = [0u8; IKM_LEN];
    fixed.try_fill_bytes(&mut first).unwrap();
    assert_eq!(first, ikm);
    assert!(!fixed.overrun);
    let mut more = [9u8; 4];
    fixed.try_fill_bytes(&mut more).unwrap();
    assert_eq!(more, [0; 4]);
    assert!(fixed.overrun);
}

#[test]
fn nothing_prints_key_material() {
    let recipient = RecipientKey::generate(&mut Bytes(vec![1; 32])).unwrap();
    let sealed = seal(
        &recipient.public_key(),
        &[0xab; KEY_LEN],
        &mut Bytes(vec![2; 32]),
    )
    .unwrap();
    assert_eq!(format!("{recipient:?}"), "RecipientKey { .. }");
    assert_eq!(format!("{sealed:?}"), "Sealed { .. }");
}

/// A vector's keying material, lent as a [`FixedRng`].
struct Owned([u8; IKM_LEN]);

impl Owned {
    fn rng(&mut self) -> FixedRng<'_> {
        FixedRng::new(&self.0)
    }
}
