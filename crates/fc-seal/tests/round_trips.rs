//! Round trips, generated (design 0001, Testing): a key sealed to a
//! recipient opens with that recipient's key, whatever the key and the
//! randomness; and any one bit changed in `enc` or the ciphertext fails the
//! open, once, as every open does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_seal::{CIPHERTEXT_LEN, ENC_LEN, RecipientKey, seal};
use proptest::prelude::*;
use rand_core::TryRng;

/// The bytes a case drew, handed out in order, over and over: a seed for
/// the key pair, another for the seal.
struct Drawn(Vec<u8>, usize);

impl TryRng for Drawn {
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
            *byte = self.0[self.1 % self.0.len()];
            self.1 += 1;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Drawn {}

fn drawn(seed: &[u8; 32]) -> Drawn {
    Drawn(seed.to_vec(), 0)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_sealed_key_opens_with_its_recipients_key(
        key in any::<[u8; 32]>(),
        recipient_seed in any::<[u8; 32]>(),
        seal_seed in any::<[u8; 32]>(),
        flip in 0usize..((ENC_LEN + CIPHERTEXT_LEN) * 8),
    ) {
        let recipient = RecipientKey::generate(&mut drawn(&recipient_seed)).unwrap();
        let sealed = seal(&recipient.public_key(), &key, &mut drawn(&seal_seed)).unwrap();
        prop_assert_ne!(&sealed.ciphertext[..32], &key[..]);
        let opened = recipient.open(&sealed.enc, &sealed.ciphertext).unwrap();
        prop_assert_eq!(*opened, key);

        // The same recipient again (its key pair comes from the seed), and
        // one bit changed anywhere in what main relays: no open.
        let mut relayed = [sealed.enc.as_slice(), sealed.ciphertext.as_slice()].concat();
        relayed[flip / 8] ^= 1 << (flip % 8);
        let again = RecipientKey::generate(&mut drawn(&recipient_seed)).unwrap();
        let (enc, ciphertext) = relayed.split_at(ENC_LEN);
        prop_assert!(again.open(enc, ciphertext).is_err());
    }
}
