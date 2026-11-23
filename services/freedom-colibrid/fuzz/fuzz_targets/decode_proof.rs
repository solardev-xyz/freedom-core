//! `c4_decode_proof` over any bytes: the checkpoint process decodes the
//! proof main fetched from the prover before verifying it (design 0014).
//! Besides finding crashes, it checks the contract the decoder documents:
//! what it returns is JSON.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(json) = colibri_stateless::decode_proof(data) {
        assert!(
            serde_json::from_str::<serde_json::Value>(&json).is_ok(),
            "the decoded proof isn't JSON"
        );
    }
});
