//! Round trips, generated (design 0001, Testing): a vault sealed with any
//! mnemonic, password and parameters opens with that password to the same
//! mnemonic and iteration count, passes the structure and password checks,
//! and doesn't open with another password. A few PBKDF2 rounds keep each
//! case quick; the vectors pin the real count.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_keys::Mnemonic;
use fc_vault::format::{SealParams, check_structure, open, seal, verify_password};
use proptest::prelude::*;

/// BIP-39 entropy: 128 to 256 bits, in steps of 32.
fn entropy() -> impl Strategy<Value = Vec<u8>> {
    (4usize..=8).prop_flat_map(|words| prop::collection::vec(any::<u8>(), words * 4))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_sealed_vault_opens_with_its_password(
        entropy in entropy(),
        password in ".{0,32}",
        salt in any::<[u8; 32]>(),
        iv in any::<[u8; 16]>(),
        iterations in 1u32..=3,
        created_at in ".{0,32}",
    ) {
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let params = SealParams { salt, iv, iterations, created_at };
        let file = seal(&mnemonic, password.as_bytes(), &params).unwrap();
        prop_assert!(check_structure(&file, true).is_ok());
        prop_assert!(verify_password(&file, password.as_bytes()).is_ok());
        let opened = open(&file, password.as_bytes()).unwrap();
        prop_assert_eq!(opened.mnemonic.phrase(), mnemonic.phrase());
        prop_assert_eq!(opened.iterations, iterations);
        let wrong = String::from(password.as_str()) + "x";
        prop_assert!(open(&file, wrong.as_bytes()).is_err());
        prop_assert!(verify_password(&file, wrong.as_bytes()).is_err());
    }
}
