//! No reply panics an operation, and nothing it returns is unchecked
//! (design 0016, "Answers the core checks"): generated replies, each the
//! scripted device's honest answer, that answer with one byte changed, any
//! bytes, or one of main's failures, with `hash_only` set at random, for
//! every kind of operation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use fc_evm::{decode_signed, eip191_digest, recover_address};
use fc_ledger::{Failed, LedgerPath, Operation, Scheme, Signed, Step};
use proptest::collection::vec;
use proptest::prelude::*;

/// One generated reply.
#[derive(Debug, Clone)]
enum Pick {
    Honest,
    Flip(usize, u8),
    Bytes(Vec<u8>),
    Failed(u8),
    Refused,
}

fn pick() -> impl Strategy<Value = (Pick, bool)> {
    (
        prop_oneof![
            4 => Just(Pick::Honest),
            3 => (any::<usize>(), 1..=255u8).prop_map(|(at, x)| Pick::Flip(at, x)),
            2 => vec(any::<u8>(), 0..300).prop_map(Pick::Bytes),
            1 => (0..5u8).prop_map(Pick::Failed),
            1 => Just(Pick::Refused),
        ],
        prop::bool::weighted(0.05),
    )
}

const CASES: [&str; 6] = [
    "tx-type0-chain-137-parity-1",
    "tx-pieces-type2-three",
    "msg-live-276",
    "typed-steps",
    "typed-hash-only-mail",
    "x402-permit2-v2",
];

fn op(kind: usize) -> (Operation, Device, Option<&'static serde_json::Value>) {
    match kind {
        0 => (
            Operation::accounts(Scheme::Live, 3, 4).unwrap(),
            Device::default(),
            None,
        ),
        1 => (
            Operation::add(LedgerPath::new(Scheme::Legacy, 9).unwrap()),
            Device::default(),
            None,
        ),
        k => {
            let case = case(CASES[(k - 2) % CASES.len()]);
            (operation(case).unwrap(), device_for(case), Some(case))
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn no_reply_panics(kind in 0..8usize, picks in vec(pick(), 1..64)) {
        let (mut op, mut device, case) = op(kind);
        let mut step = op.start();
        let mut index = 0;
        let mut picks = picks.into_iter();
        let done = loop {
            match step {
                Step::Send(exchange) => {
                    let apdu = exchange.apdu.into_bytes();
                    let (pick, shown) = picks.next().unwrap_or((Pick::Honest, false));
                    let honest = relay(index, &apdu, device.answer(&apdu));
                    let owned = match (pick, honest) {
                        (Pick::Honest, honest) => honest,
                        (Pick::Flip(at, x), Owned::Answer(mut bytes, _)) => {
                            let at = at % bytes.len();
                            bytes[at] ^= x;
                            Owned::Answer(bytes, shown)
                        }
                        (Pick::Flip(..), honest) => honest,
                        (Pick::Bytes(bytes), _) => Owned::Answer(bytes, shown),
                        (Pick::Failed(n), _) => Owned::Failed(
                            [Failed::NotFound, Failed::Busy, Failed::Disconnected, Failed::Unresponsive, Failed::Timeout][n as usize],
                        ),
                        (Pick::Refused, _) => Owned::Refused,
                    };
                    index += 1;
                    prop_assert!(index < 5000);
                    step = op.answer(owned.as_reply());
                }
                Step::Done(done) => break done,
            }
        };
        // Whatever ended it, nothing unchecked came out.
        let Some(case) = case else {
            return Ok(());
        };
        let address = account(&case["record"]).address;
        match done {
            Ok(Signed::Transaction(tx)) => {
                let decoded = decode_signed(&tx.raw).unwrap();
                prop_assert_eq!(decoded.signer(), Some(address));
            }
            Ok(Signed::Signature(signature)) => {
                let digest = match case["operation"].as_str().unwrap() {
                    "sign.message" => eip191_digest(&unhex(case["request"]["message"].as_str().unwrap())),
                    _ => typed_hash(case),
                };
                prop_assert_eq!(recover_address(&digest, &signature), Ok(address));
            }
            Ok(other) => prop_assert!(false, "{other:?}"),
            Err(_) => {}
        }
    }
}
