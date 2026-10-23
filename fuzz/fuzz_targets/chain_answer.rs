//! fc-chain's reading of an RPC endpoint's answer (design 0005): the body
//! decoded as Node decodes it, then read as JSON-RPC, then classified as a
//! broadcast's outcome would be. Bodies come from the network.
//!
//! The first two bytes are the HTTP status, the rest the body. It checks,
//! besides panics, that an answer's result lies inside its text.

#![no_main]

use fc_chain::{Outcome, TxHash, classify_broadcast_answer, decode_answer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((status, body)) = data.split_first_chunk::<2>() else {
        return;
    };
    let answer = decode_answer(u16::from_be_bytes(*status) % 600, body.to_vec());
    if let Ok(answer) = &answer {
        let text = answer.text();
        if let Some(Some(span)) = answer.result_span() {
            assert!(text.get(span).is_some());
        }
        match answer.outcome() {
            Outcome::Result(result) => {
                if let Some(result) = result {
                    assert!(text.contains(result));
                }
            }
            Outcome::NodeError(_) => {}
        }
    }
    let hash =
        TxHash::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let _ = classify_broadcast_answer(&hash, &answer);
});
