//! fc-seal (design 0008, "Keys"): `RecipientKey::open` over a relayed
//! `enc` and ciphertext, and `seal` to any recipient.
//!
//! The first byte picks what the rest is:
//! - **even:** a recipient's seed (32 bytes), then what main would relay,
//!   cut anywhere: `open` must refuse it, since nothing but a seal to that
//!   recipient opens, and nothing here seals to it;
//! - **odd:** a recipient's public key, a key and a seed: `seal` succeeds
//!   exactly when `valid_recipient` says the key is one, and a seal to a
//!   recipient made from a seed opens to the key.

#![no_main]

use fc_seal::{RecipientKey, seal, valid_recipient};
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

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        let Some((seed, relayed)) = rest.split_first_chunk::<32>() else {
            return;
        };
        let recipient = RecipientKey::generate(&mut Drawn(seed, 0)).unwrap();
        let cut = usize::from(mode / 2).min(relayed.len());
        let (enc, ciphertext) = relayed.split_at(cut);
        assert!(recipient.open(enc, ciphertext).is_err());
        return;
    }
    let Some((public, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((key, seed)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let sealed = seal(public, key, &mut Drawn(seed, 0));
    assert_eq!(sealed.is_ok(), valid_recipient(public));
    let recipient = RecipientKey::generate(&mut Drawn(public, 0)).unwrap();
    let sealed = seal(&recipient.public_key(), key, &mut Drawn(seed, 0)).unwrap();
    assert_eq!(
        *recipient.open(&sealed.enc, &sealed.ciphertext).unwrap(),
        *key
    );
});
