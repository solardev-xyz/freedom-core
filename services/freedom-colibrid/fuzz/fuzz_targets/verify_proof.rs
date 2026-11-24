//! The verifier over any proof and any answers to its data requests, as
//! the checkpoint process runs it (design 0014): `eth_getBlockByNumber
//! ["latest",false]` on a memory store. The input is a proof (its length
//! first, 4 bytes, little-endian), then each answer the same way, given in
//! order to the requests the verifier makes, for at most a few steps.
//!
//! Each input starts cold: a fresh memory store and the C core's in-process
//! caches cleared, so what an input does never depends on the inputs before
//! it, and an artifact reproduces on its own.

#![no_main]

use colibri_stateless::{MemoryStorage, Step, Verifier};
use libfuzzer_sys::fuzz_target;

/// The most steps one input runs.
const STEPS: usize = 8;

/// The next length-prefixed piece of `input`.
fn piece<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = input.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_le_bytes(*len))
        .unwrap_or(usize::MAX)
        .min(rest.len());
    let (piece, rest) = rest.split_at(len);
    *input = rest;
    Some(piece)
}

fuzz_target!(|data: &[u8]| {
    colibri_stateless::register_storage(MemoryStorage::new());
    colibri_stateless::reset_caches();
    let mut input = data;
    let Some(proof) = piece(&mut input) else {
        return;
    };
    let Ok(mut verifier) = Verifier::new(
        proof,
        "eth_getBlockByNumber",
        r#"["latest",false]"#,
        1,
        None,
        2,
    ) else {
        return;
    };
    verifier.set_min_latest_block_ts(0);
    for _ in 0..STEPS {
        match verifier.execute() {
            Ok(Step::Pending { requests }) => {
                for request in requests {
                    match piece(&mut input) {
                        Some(answer) => request.set_response(answer, 0),
                        None => request.set_error("no more input", 0),
                    }
                }
            }
            _ => break,
        }
    }
});
