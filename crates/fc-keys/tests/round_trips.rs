//! Round trips, generated (design 0001, Testing):
//!
//! - **mnemonics:** any BIP-39 entropy gives a phrase that parses back to
//!   itself, with the word count its length sets;
//! - **Bee keystores:** a key derived from any mnemonic, encrypted with any
//!   password, decrypts with that password to the same key and address,
//!   and not with another. Scrypt's fixed cost (N = 2^17) keeps this to a
//!   few cases; the vectors pin the format.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_keys::keystore::{KeystoreParams, decrypt, encrypt};
use fc_keys::{DerivationPath, Mnemonic, derive_secp256k1, is_valid_mnemonic};
use proptest::prelude::*;

/// BIP-39 entropy: 128 to 256 bits, in steps of 32.
fn entropy() -> impl Strategy<Value = Vec<u8>> {
    (4usize..=8).prop_flat_map(|words| prop::collection::vec(any::<u8>(), words * 4))
}

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config(256))]

    #[test]
    fn a_phrase_parses_back_to_itself(entropy in entropy()) {
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.phrase();
        prop_assert_eq!(phrase.split(' ').count(), entropy.len() * 3 / 4);
        prop_assert!(is_valid_mnemonic(phrase));
        let parsed = Mnemonic::parse(phrase).unwrap();
        prop_assert_eq!(parsed.phrase(), phrase);
    }
}

proptest! {
    #![proptest_config(config(3))]

    #[test]
    fn a_keystore_decrypts_with_its_password(
        entropy in entropy(),
        index in 0u32..1000,
        password in ".{0,24}",
        salt in any::<[u8; 32]>(),
        iv in any::<[u8; 16]>(),
        uuid in any::<[u8; 16]>(),
    ) {
        let seed = Mnemonic::from_entropy(&entropy).unwrap().to_seed();
        let path: DerivationPath = format!("m/44'/60'/0'/0/{index}").parse().unwrap();
        let key = derive_secp256k1(&seed, &path).unwrap();
        let json = encrypt(&key, &password, &KeystoreParams { salt, iv, uuid }).unwrap();
        let decrypted = decrypt(&json, &password).unwrap();
        prop_assert_eq!(decrypted.address(), key.address());
        prop_assert_eq!(*decrypted.to_secret_bytes(), *key.to_secret_bytes());
        let wrong = format!("{password}x");
        prop_assert!(decrypt(&json, &wrong).is_err());
    }
}
