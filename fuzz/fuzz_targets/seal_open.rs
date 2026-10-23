//! fc-seal (design 0008, "Keys"): `RecipientKey::open` over a relayed
//! `enc` and ciphertext, and `seal` to any recipient.
//!
//! The first byte picks what the rest is:
//! - **even:** a recipient's seed (32 bytes), then what main would relay,
//!   cut anywhere. Those bytes can be a genuine seal to that recipient (a
//!   seed can carry one), so `open` is only run, never told the answer.
//!   What is checked is what the target knows either way: an `enc` that
//!   isn't 32 bytes, or a ciphertext that isn't 48, never opens; and what
//!   opens is a seal to that recipient, so it opens again to the same key,
//!   to no other recipient, and with no byte changed;
//! - **odd:** a recipient's public key, a key and a seed: `seal` succeeds
//!   exactly when `valid_recipient` says the key is one. A seal to a
//!   recipient made from a seed opens to the key; another recipient
//!   doesn't open it, and neither does that recipient once a byte of it is
//!   changed (the byte by the first byte's upper bits, the change by the
//!   key's first byte).

#![no_main]

use fc_seal::{CIPHERTEXT_LEN, ENC_LEN, KEY_LEN, RecipientKey, seal, valid_recipient};
use libfuzzer_sys::fuzz_target;
use rand_core::TryRng;

/// Hands out `bytes`, over and over.
struct Drawn<'a>(&'a [u8], usize);

impl TryRng for Drawn<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dst {
            *byte = self
                .0
                .get(self.1 % self.0.len().max(1))
                .copied()
                .unwrap_or(0);
            self.1 += 1;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Drawn<'_> {}

/// The recipient a seed gives, as `RecipientKey::generate` draws it.
fn recipient(seed: &[u8]) -> RecipientKey {
    RecipientKey::generate(&mut Drawn(seed, 0)).unwrap()
}

/// Another recipient than `seed`'s: the seed with its first byte changed.
/// `None` in the (never seen) case of the same public key.
fn other_recipient(seed: &[u8; 32]) -> Option<RecipientKey> {
    let mut other = *seed;
    other[0] ^= 1;
    let other = recipient(&other);
    (other.public_key() != recipient(seed).public_key()).then_some(other)
}

/// `enc || ciphertext` with the byte at `at` XORed with `mask` (not 0).
fn changed(
    enc: &[u8; ENC_LEN],
    ciphertext: &[u8; CIPHERTEXT_LEN],
    at: usize,
    mask: u8,
) -> ([u8; ENC_LEN], [u8; CIPHERTEXT_LEN]) {
    let (mut enc, mut ciphertext) = (*enc, *ciphertext);
    if at < ENC_LEN {
        enc[at] ^= mask;
    } else {
        ciphertext[at - ENC_LEN] ^= mask;
    }
    (enc, ciphertext)
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        let Some((seed, relayed)) = rest.split_first_chunk::<32>() else {
            return;
        };
        let cut = usize::from(mode / 2).min(relayed.len());
        let (enc, ciphertext) = relayed.split_at(cut);
        // Run for robustness: whether these bytes open isn't known here.
        let opened = recipient(seed).open(enc, ciphertext);
        let (Ok(enc), Ok(ciphertext)) = (
            <&[u8; ENC_LEN]>::try_from(enc),
            <&[u8; CIPHERTEXT_LEN]>::try_from(ciphertext),
        ) else {
            assert!(opened.is_err());
            return;
        };
        let Ok(key) = opened else {
            return;
        };
        // A genuine seal to this recipient: the same key again, and nothing
        // for another recipient or for any one-byte change of it.
        assert_eq!(*recipient(seed).open(enc, ciphertext).unwrap(), *key);
        if let Some(other) = other_recipient(seed) {
            assert!(other.open(enc, ciphertext).is_err());
        }
        for at in 0..ENC_LEN + CIPHERTEXT_LEN {
            let (enc, ciphertext) = changed(enc, ciphertext, at, 1 << (at % 8));
            assert!(recipient(seed).open(&enc, &ciphertext).is_err());
        }
        return;
    }
    let Some((public, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((key, seed)) = rest.split_first_chunk::<KEY_LEN>() else {
        return;
    };
    let sealed = seal(public, key, &mut Drawn(seed, 0));
    assert_eq!(sealed.is_ok(), valid_recipient(public));
    // A seal this target makes, so what may open it is known.
    let sealed = seal(&recipient(public).public_key(), key, &mut Drawn(seed, 0)).unwrap();
    assert_eq!(
        *recipient(public)
            .open(&sealed.enc, &sealed.ciphertext)
            .unwrap(),
        *key
    );
    if let Some(other) = other_recipient(public) {
        assert!(other.open(&sealed.enc, &sealed.ciphertext).is_err());
    }
    let at = usize::from(mode / 2) % (ENC_LEN + CIPHERTEXT_LEN);
    let mask = if key[0] == 0 { 0x80 } else { key[0] };
    let (enc, ciphertext) = changed(&sealed.enc, &sealed.ciphertext, at, mask);
    assert!(recipient(public).open(&enc, &ciphertext).is_err());
});
