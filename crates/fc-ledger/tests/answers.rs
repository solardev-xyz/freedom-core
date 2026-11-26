//! The answers the core checks and the bounds it keeps (design 0016,
//! LDG-1's row): each status at each step of each operation; main's
//! failures; an answer a byte short or long; an address whose text isn't
//! its key's; a signature that recovers to another key, over another
//! digest, or with a high `s`; the Q23 order; the bounds at 255 and 256,
//! 65,535 and 65,536, 2,048 and 2,049; the names at the definition APDU's
//! edge.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use fc_evm::{Transaction, typed_data_parse};
use fc_ledger::bounds::Bound;
use fc_ledger::{
    Cause, Failed, LedgerCode, LedgerPath, Operation, ProtocolFault, Refusal, Reply, Scheme,
    SignatureFault, Signed, Step,
};
use serde_json::{Value, json};

const STATUSES: [u16; 10] = [
    0x5515, 0x6982, 0x6985, 0x5501, 0x6a80, 0x6511, 0x6d00, 0x6e00, 0x6e01, 0x6f00,
];

/// The operations of the vectors' `*-steps` cases, each with its device.
/// A fresh operation and its device.
type Make = Box<dyn Fn() -> (Operation, Device)>;

fn steps() -> Vec<(&'static str, Make)> {
    let from_case = |id: &'static str| -> Make {
        Box::new(move || {
            let case = case(id);
            (operation(case).unwrap(), device_for(case))
        })
    };
    vec![
        (
            "discovery",
            Box::new(|| {
                (
                    Operation::accounts(Scheme::Live, 0, 2).unwrap(),
                    Device::default(),
                )
            }),
        ),
        (
            "add",
            Box::new(|| {
                let path = LedgerPath::new(Scheme::Legacy, 3).unwrap();
                (Operation::add(path), Device::default())
            }),
        ),
        ("transaction", from_case("tx-steps")),
        (
            "legacy transaction",
            from_case("tx-pieces-legacy-shrink-254"),
        ),
        ("message", from_case("msg-steps")),
        ("typed data", from_case("typed-steps")),
        ("hash only", from_case("typed-hash-only-mail")),
    ]
}

fn code(run: &Run) -> LedgerCode {
    match &run.done {
        Err(failure) => failure.code,
        Ok(signed) => panic!("signed: {signed:?}"),
    }
}

fn cause(run: &Run) -> Cause {
    run.done.as_ref().unwrap_err().cause.clone()
}

fn is_signing(apdu: &[u8]) -> bool {
    matches!(apdu[..2], [0xe0, 0x0c])
}

#[test]
fn each_status_at_each_step() {
    let mut runs = 0;
    for (name, make) in steps() {
        let (mut op, mut device) = make();
        let clean = run_device(&mut op, &mut device);
        assert!(clean.done.is_ok(), "{name}: {:?}", clean.done);
        for at in 0..clean.apdus.len() {
            for status in STATUSES {
                let (mut op, mut device) = make();
                device.fault = Some((at, Fault::Status(status)));
                let run = run_device(&mut op, &mut device);
                runs += 1;
                let first_definition = at == 2 && clean.apdus[2][..4] == [0xe0, 0x1a, 0x00, 0x00];
                if status == 0x6d00 && first_definition {
                    // Q23: the hash-only form, and its signature.
                    assert!(
                        matches!(run.done, Ok(Signed::Signature(_))),
                        "{name} at {at}"
                    );
                    assert_eq!(run.apdus.len(), 4, "{name}");
                    assert_eq!(run.apdus[3][..4], [0xe0, 0x0c, 0x00, 0x00], "{name}");
                    continue;
                }
                assert_eq!(
                    code(&run),
                    LedgerCode::for_status(status),
                    "{name} at {at}: {status:04x}"
                );
                assert_eq!(cause(&run), Cause::Status(status), "{name} at {at}");
                assert_eq!(
                    run.apdus,
                    clean.apdus[..=at],
                    "{name} at {at}: nothing after"
                );
            }
        }
    }
    // Seven operations of 38 APDUs in all, ten statuses at each.
    assert_eq!(runs, 380);
}

#[test]
fn mains_failures_and_refusals_at_each_step() {
    for (name, make) in steps() {
        let (mut op, mut device) = make();
        let clean = run_device(&mut op, &mut device);
        for at in 0..clean.apdus.len() {
            for (owned, want) in [
                (Owned::Failed(Failed::NotFound), LedgerCode::DeviceNotFound),
                (Owned::Failed(Failed::Busy), LedgerCode::Busy),
                (
                    Owned::Failed(Failed::Disconnected),
                    LedgerCode::Disconnected,
                ),
                (
                    Owned::Failed(Failed::Unresponsive),
                    LedgerCode::Unresponsive,
                ),
                (Owned::Failed(Failed::Timeout), LedgerCode::Timeout),
                (Owned::Refused, LedgerCode::Unknown),
            ] {
                let (mut op, mut device) = make();
                let run = run(&mut op, |index, apdu| {
                    let answer = device.answer(apdu);
                    if index == at {
                        owned.clone()
                    } else {
                        relay(index, apdu, answer)
                    }
                });
                assert_eq!(code(&run), want, "{name} at {at}: {owned:?}");
                assert_eq!(run.apdus.len(), at + 1, "{name} at {at}");
            }
            // The device unplugged mid-read.
            let (mut op, mut device) = make();
            device.fault = Some((at, Fault::Disconnect));
            let run = run_device(&mut op, &mut device);
            assert_eq!(code(&run), LedgerCode::Disconnected, "{name} at {at}");
        }
    }
}

#[test]
fn an_answer_a_byte_short_or_long() {
    for (name, make) in steps() {
        let (mut op, mut device) = make();
        let clean = run_device(&mut op, &mut device);
        for at in 0..clean.apdus.len() {
            for fault in [Fault::Long, Fault::Short] {
                let (mut op, mut device) = make();
                // A Nano S's 6D00 has no data to cut or lengthen.
                let natural = !device.fields && matches!(clean.apdus[at][1], 0x1a | 0x1c);
                let empty = matches!(clean.apdus[at][1], 0x1a | 0x1c)
                    || (matches!(clean.apdus[at][1], 0x04 | 0x08) && at + 1 < clean.apdus.len());
                if natural || (fault == Fault::Short && empty) {
                    continue;
                }
                device.fault = Some((at, fault));
                let run = run_device(&mut op, &mut device);
                let signs = is_signing(&clean.apdus[at])
                    || (matches!(clean.apdus[at][1], 0x04 | 0x08) && at + 1 == clean.apdus.len());
                if signs {
                    assert_eq!(
                        code(&run),
                        LedgerCode::BadSignature,
                        "{name} at {at}: {fault:?}"
                    );
                    assert_eq!(cause(&run), Cause::Signature(SignatureFault::Length));
                } else {
                    assert_eq!(code(&run), LedgerCode::Unknown, "{name} at {at}: {fault:?}");
                    assert!(matches!(cause(&run), Cause::Answer(_)), "{name} at {at}");
                }
                assert_eq!(run.apdus.len(), at + 1, "{name} at {at}");
            }
        }
    }
}

#[test]
fn an_address_whose_text_isnt_its_keys() {
    for (name, make) in steps() {
        let (mut op, mut device) = make();
        device.fault = Some((0, Fault::KeyNotAddress));
        let run = run_device(&mut op, &mut device);
        assert_eq!(code(&run), LedgerCode::Unknown, "{name}");
        assert_eq!(
            cause(&run),
            Cause::Answer(fc_ledger::AnswerFault::KeyNotAddress),
            "{name}"
        );
        assert_eq!(run.apdus.len(), 1, "{name}");
        // Another key with its own address: another device.
        let (mut op, mut device) = make();
        device.fault = Some((0, Fault::OtherAddress));
        let run = run_device(&mut op, &mut device);
        let other = *other_key().address().as_bytes();
        match (name, &run.done) {
            ("discovery", Ok(Signed::Accounts(accounts))) => assert_eq!(accounts[0].address, other),
            ("add", Ok(Signed::Added(account))) => assert_eq!(account.address, other),
            (_, _) => {
                assert_eq!(code(&run), LedgerCode::WrongDevice, "{name}");
                assert_eq!(run.apdus.len(), 1, "{name}");
            }
        }
    }
}

#[test]
fn an_address_answer_out_of_form() {
    let account = account_at("44'/60'/0'/0/0");
    type Change = fn(&mut Vec<u8>);
    let tamper: [(&str, Change); 7] = [
        ("a compressed prefix", |a| a[1] = 0x03),
        ("a key length of 64", |a| a[0] = 64),
        ("an address length of 41", |a| a[66] = 41),
        ("a character outside hex", |a| a[67] = b'g'),
        ("a checksum broken", |a| {
            // Swap one letter's case: mixed case then must be EIP-55.
            let at = (67..107).find(|i| a[*i].is_ascii_alphabetic()).unwrap();
            a[at] ^= 0x20;
        }),
        ("not UTF-8", |a| a[67] = 0xff),
        ("no address", |a| a.truncate(67)),
    ];
    for (what, change) in tamper {
        let mut op = Operation::sign_message(account.clone(), b"m".to_vec()).unwrap();
        let mut device = Device::default();
        let run = run(&mut op, |index, apdu| {
            let mut answer = device.answer(apdu);
            if let (0, Answer::Bytes(bytes)) = (index, &mut answer) {
                let status = bytes.split_off(bytes.len() - 2);
                change(bytes);
                bytes.extend_from_slice(&status);
            }
            relay(index, apdu, answer)
        });
        assert_eq!(code(&run), LedgerCode::Unknown, "{what}");
        assert!(matches!(cause(&run), Cause::Answer(_)), "{what}");
    }
    // An all-lowercase address is read.
    let mut op = Operation::sign_message(account.clone(), b"m".to_vec()).unwrap();
    let mut device = Device::default();
    let run = run(&mut op, |index, apdu| {
        let mut answer = device.answer(apdu);
        if let (0, Answer::Bytes(bytes)) = (index, &mut answer) {
            bytes[67..107].make_ascii_lowercase();
        }
        relay(index, apdu, answer)
    });
    assert!(run.done.is_ok(), "{:?}", run.done);
}

#[test]
fn the_app_must_be_ethereum() {
    let account = account_at("44'/60'/0'/0/0");
    for (name, version, ok) in [
        ("Ethereum", "1.9.0", true),
        ("Ethereum", "", true),
        ("Polygon", "1.13.0", false),
        ("ethereum", "1.13.0", false),
        ("Ethereum ", "1.13.0", false),
        ("BOLOS", "2.1.0", false),
        ("", "", false),
    ] {
        let mut op = Operation::sign_message(account.clone(), b"m".to_vec()).unwrap();
        let mut device = Device::default();
        device.app_name = name.into();
        device.app_version = version.into();
        let run = run_device(&mut op, &mut device);
        if ok {
            assert!(run.done.is_ok(), "{name}");
        } else {
            assert_eq!(code(&run), LedgerCode::EthAppNotOpen, "{name}");
            assert_eq!(run.apdus.len(), 2, "{name}: nothing after B0 01");
            assert_eq!(run.done.unwrap_err().app_version.as_deref(), Some(version));
        }
    }
    // A format other than 1.
    let mut op = Operation::sign_message(account, b"m".to_vec()).unwrap();
    let mut device = Device::default();
    let run = run(&mut op, |index, apdu| {
        let mut answer = device.answer(apdu);
        if let (1, Answer::Bytes(bytes)) = (index, &mut answer) {
            bytes[0] = 2;
        }
        relay(index, apdu, answer)
    });
    assert_eq!(code(&run), LedgerCode::EthAppNotOpen);
}

#[test]
fn a_signature_by_another_key_over_another_digest_or_high_s() {
    let signers: Vec<(&str, &str)> = vec![
        ("legacy", "tx-type0-chain-137-parity-1"),
        ("legacy, wide chain", "tx-type0-chain-2-64-parity-0"),
        ("EIP-1559", "tx-type2-chain-1-parity-0"),
        ("message", "msg-live-276"),
        ("typed data", "typed-mail"),
        ("hash only", "typed-hash-only-safe-tx"),
    ];
    for (name, id) in signers {
        let case = case(id);
        let (mut op, mut device) = (operation(case).unwrap(), device_for(case));
        let clean = run_device(&mut op, &mut device);
        assert!(clean.done.is_ok(), "{name}: {:?}", clean.done);
        let at = clean.apdus.len() - 1;
        let legacy = case["request"]["tx"]["type"] == 0;
        let mut faults = vec![
            (Fault::OtherKey, SignatureFault::Signer),
            (Fault::OtherDigest, SignatureFault::Signer),
            (Fault::HighS, SignatureFault::Recovery),
            (Fault::FlipV, SignatureFault::Signer),
        ];
        // A v the operation can't have: a message's for a transaction, and
        // past its two values.
        let base = legacy.then(|| {
            let chain = fc_evm::parse_unsigned(case["request"]["tx"]["chain_id"].as_str().unwrap())
                .unwrap();
            let prime = chain
                .to_minimal_be()
                .iter()
                .take(4)
                .fold(0u64, |a, b| (a << 8) | *b as u64);
            ((prime * 2 + 35) % 256) as u8
        });
        for v in [0u8, 1, 2, 26, 27, 28, 29, 35, 36, 53, 54, 255] {
            let fits = match (case["operation"].as_str().unwrap(), base) {
                ("sign.transaction", Some(base)) => v == base || v == base.wrapping_add(1),
                ("sign.transaction", None) => v <= 1,
                _ => v == 27 || v == 28,
            };
            if !fits {
                faults.push((Fault::V(v), SignatureFault::V));
            }
        }
        for (fault, why) in faults {
            let (mut op, mut device) = (operation(case).unwrap(), device_for(case));
            device.fault = Some((at, fault));
            let run = run_device(&mut op, &mut device);
            assert_eq!(code(&run), LedgerCode::BadSignature, "{name}: {fault:?}");
            // A flipped parity recovers another key, or none.
            if fault != Fault::FlipV {
                assert_eq!(cause(&run), Cause::Signature(why), "{name}: {fault:?}");
            }
        }
    }
}

#[test]
fn the_hash_only_form_only_after_6d00_to_the_first_definition_and_mains_word() {
    let case = case("typed-steps");
    // 6D00 to the first E0 1A without hash_only: nothing more is sent.
    let (mut op, mut device) = (operation(case).unwrap(), device_for(case));
    device.fault = Some((2, Fault::Status(0x6d00)));
    let stopped = run(&mut op, |_, apdu| match device.answer(apdu) {
        Answer::Bytes(bytes) => Owned::Answer(bytes, false),
        Answer::Disconnected => Owned::Failed(Failed::Disconnected),
    });
    assert_eq!(code(&stopped), LedgerCode::Unknown);
    assert_eq!(cause(&stopped), Cause::HashOnlyNotShown);
    assert_eq!(stopped.apdus.len(), 3);
    // hash_only on any other answer: a protocol error.
    let clean = run_device(&mut operation(case).unwrap(), &mut device_for(case));
    for at in 0..clean.apdus.len() {
        let (mut op, mut device) = (operation(case).unwrap(), device_for(case));
        let stopped = run(&mut op, |index, apdu| match device.answer(apdu) {
            Answer::Bytes(bytes) => Owned::Answer(bytes, index == at),
            Answer::Disconnected => Owned::Failed(Failed::Disconnected),
        });
        assert_eq!(code(&stopped), LedgerCode::Unknown, "at {at}");
        assert_eq!(
            cause(&stopped),
            Cause::Protocol(ProtocolFault::HashOnly),
            "at {at}"
        );
        assert_eq!(stopped.apdus.len(), at + 1);
    }
    // 6D00 anywhere else is today's mapping, never the fallback.
    for at in (0..clean.apdus.len()).filter(|at| *at != 2) {
        let (mut op, mut device) = (operation(case).unwrap(), device_for(case));
        device.fault = Some((at, Fault::Status(0x6d00)));
        let run = run_device(&mut op, &mut device);
        assert_eq!(code(&run), LedgerCode::EthAppNotOpen, "at {at}");
        assert!(run.apdus.iter().all(|a| a[..4] != [0xe0, 0x0c, 0x00, 0x00]));
    }
    // The hash-only APDU carries fc-evm's two hashes of the bound data.
    let (mut op, mut device) = (operation(case).unwrap(), device_for(case));
    device.fields = false;
    let run = run_device(&mut op, &mut device);
    assert!(run.done.is_ok());
    let typed = &case["request"]["typed_data"];
    let parsed = typed_data_parse(&typed["domain"], &typed["types"], &typed["message"]).unwrap();
    let path = account(&case["record"]).path.encode();
    let mut want = vec![0xe0, 0x0c, 0x00, 0x00, (path.len() + 64) as u8];
    want.extend_from_slice(&path);
    want.extend_from_slice(&parsed.domain_separator);
    want.extend_from_slice(&parsed.struct_hash);
    assert_eq!(run.apdus[3], want);
    assert!(run.confirms[3]);
}

#[test]
fn replies_out_of_order_or_bounds() {
    let account = account_at("44'/60'/0'/0/0");
    let mut op = Operation::sign_message(account.clone(), b"m".to_vec()).unwrap();
    let Step::Done(Err(failure)) = op.answer(Reply::answer(&[0x90, 0x00])) else {
        panic!("an answer before the first APDU")
    };
    assert_eq!(failure.cause, Cause::Protocol(ProtocolFault::Order));
    let mut op = Operation::sign_message(account.clone(), b"m".to_vec()).unwrap();
    assert!(matches!(op.start(), Step::Send(_)));
    assert!(matches!(op.start(), Step::Done(Err(_))));
    for bad in [vec![], vec![0x90], vec![0u8; 261]] {
        let mut op = Operation::sign_message(account.clone(), b"m".to_vec()).unwrap();
        op.start();
        let Step::Done(Err(failure)) = op.answer(Reply::answer(&bad)) else {
            panic!("{} bytes", bad.len())
        };
        assert_eq!(failure.code, LedgerCode::Unknown);
        assert_eq!(failure.cause, Cause::Protocol(ProtocolFault::AnswerBounds));
        assert!(matches!(
            op.answer(Reply::answer(&[0x90, 0x00])),
            Step::Done(Err(_))
        ));
    }
    // After the end, nothing more.
    let mut op = Operation::sign_message(account, b"m".to_vec()).unwrap();
    let mut device = Device::default();
    let done = run_device(&mut op, &mut device);
    assert!(done.done.is_ok());
    let Step::Done(Err(failure)) = op.answer(Reply::answer(&[0x90, 0x00])) else {
        panic!("an answer after the end")
    };
    assert_eq!(failure.cause, Cause::Protocol(ProtocolFault::Order));
}

fn refusal_of<T>(result: Result<T, Refusal>) -> Refusal {
    match result {
        Err(refusal) => refusal,
        Ok(_) => panic!("accepted"),
    }
}

/// `{ key: value }` with a computed key.
fn object(key: &str, value: Value) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(key.to_owned(), value);
    Value::Object(map)
}

/// Typed data under abandon-12's first live account: its run over the
/// scripted device, or its refusal.
fn typed(types: Value, message: Value) -> Result<Run, Refusal> {
    let domain = json!({ "name": "B" });
    // Typed data 0002 refuses has no hash: the parse refuses it first.
    let hash = fc_evm::typed_data_hash(&domain, &types, &message).unwrap_or_default();
    let account = account_at("44'/60'/0'/0/0");
    let typed = json!({ "domain": domain, "types": types, "message": message });
    let mut op = typed_operation(account, &typed, &hash)?;
    let mut device = Device::default();
    device.typed_hash = Some(hash);
    let run = run_device(&mut op, &mut device);
    assert!(run.done.is_ok(), "{:?}", run.done);
    Ok(run)
}

#[test]
fn arrays_and_fixed_sizes_at_255_and_256() {
    for (n, ok) in [(255usize, true), (256, false)] {
        let items: Vec<u8> = vec![1; n];
        let dynamic = typed(
            json!({ "M": [{ "name": "v", "type": "uint8[]" }] }),
            json!({ "v": items }),
        );
        let fixed = typed(
            json!({ "M": [{ "name": "v", "type": format!("uint8[{n}]") }] }),
            json!({ "v": items }),
        );
        if ok {
            let run = dynamic.unwrap();
            assert!(
                run.apdus
                    .iter()
                    .any(|a| a[..] == [0xe0, 0x1c, 0x00, 0x0f, 1, 255])
            );
            fixed.unwrap();
        } else {
            assert_eq!(
                refusal_of(dynamic),
                Refusal::TooLarge(Bound::ArrayEntries(256))
            );
            assert_eq!(refusal_of(fixed), Refusal::TooLarge(Bound::FixedSize(256)));
        }
    }
}

#[test]
fn values_at_65535_and_65536_bytes() {
    for (n, ok) in [(65_535usize, true), (65_536, false)] {
        let result = typed(
            json!({ "M": [{ "name": "v", "type": "bytes" }] }),
            json!({ "v": format!("0x{}", "ab".repeat(n)) }),
        );
        if ok {
            let run = result.unwrap();
            // The message's value: the pieces after its root.
            let root = run
                .apdus
                .iter()
                .rposition(|a| a[..4] == [0xe0, 0x1c, 0x00, 0x00])
                .unwrap();
            let pieces: Vec<&Vec<u8>> = run.apdus[root..]
                .iter()
                .filter(|a| a[1] == 0x1c && a[3] == 0xff)
                .collect();
            assert_eq!(pieces.len(), 258);
            let joined: Vec<u8> = pieces.iter().flat_map(|a| a[5..].to_vec()).collect();
            assert_eq!(joined[..2], [0xff, 0xff]);
            assert_eq!(joined.len(), 2 + n);
            assert!(pieces[..257].iter().all(|a| a[2] == 0x01 && a[4] == 255));
            assert_eq!(pieces[257][..5], [0xe0, 0x1c, 0x00, 0xff, 2]);
        } else {
            assert_eq!(refusal_of(result), Refusal::TooLarge(Bound::Value(65_536)));
        }
    }
    let text = typed(
        json!({ "M": [{ "name": "v", "type": "string" }] }),
        json!({ "v": "é".repeat(32_768) }),
    );
    assert_eq!(refusal_of(text), Refusal::TooLarge(Bound::Value(65_536)));
}

#[test]
fn typed_data_of_2048_and_2049_apdus() {
    // Seven arrays of 255 entries and one of n: 1,810 + n APDUs.
    let build = |n: usize| {
        let mut fields = Vec::new();
        let mut message = serde_json::Map::new();
        for k in 0..8 {
            fields.push(json!({ "name": format!("f{k}"), "type": "uint8[]" }));
            message.insert(format!("f{k}"), json!(vec![1; if k < 7 { 255 } else { n }]));
        }
        typed(json!({ "M": fields }), Value::Object(message))
    };
    assert_eq!(build(238).unwrap().apdus.len(), 2048);
    assert_eq!(refusal_of(build(239)), Refusal::TooLarge(Bound::Apdus));
}

#[test]
fn messages_of_2048_and_2049_apdus() {
    let account = account_at("44'/60'/0'/0/0");
    // 125 bytes in the first piece, 150 in each next: 2,046 pieces.
    let len = 125 + 2045 * 150;
    let mut op = Operation::sign_message(account.clone(), vec![7; len]).unwrap();
    let run = run_device(&mut op, &mut Device::default());
    assert!(run.done.is_ok());
    assert_eq!(run.apdus.len(), 2048);
    assert_eq!(
        refusal_of(Operation::sign_message(account.clone(), vec![7; len + 1])),
        Refusal::TooLarge(Bound::Apdus)
    );
    assert_eq!(
        refusal_of(Operation::sign_message(account, Vec::new())),
        Refusal::EmptyMessage
    );
}

#[test]
fn transactions_of_2048_and_2049_apdus() {
    let account = account_at("44'/60'/0'/0/0");
    let tx = |len: usize| {
        Transaction::from_json(&json!({
            "type": 2, "chain_id": "1", "nonce": "0", "gas_limit": "30000000",
            "to": "0x8ba1f109551bD432803012645Ac136ddd64DBA72", "value": "0",
            "data": format!("0x{}", "ab".repeat(len)),
            "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1"
        }))
        .unwrap()
    };
    // P ‖ T of exactly 2,046 pieces of 255.
    let target = 2046 * 255;
    let mut len = target;
    loop {
        let payload = 21 + tx(len).prepare().unwrap().unsigned().len();
        if payload == target {
            break;
        }
        len = len + target - payload;
    }
    let mut op = Operation::sign_transaction(account.clone(), &tx(len)).unwrap();
    let run = run_device(&mut op, &mut Device::default());
    assert!(
        matches!(run.done, Ok(Signed::Transaction(_))),
        "{:?}",
        run.done
    );
    assert_eq!(run.apdus.len(), 2048);
    assert_eq!(
        refusal_of(Operation::sign_transaction(account, &tx(len + 1))),
        Refusal::TooLarge(Bound::Apdus)
    );
}

#[test]
fn names_at_the_definition_apdus_edge() {
    // A string field's name of 253 characters: a definition of 255 bytes,
    // its length byte 253.
    let name = "a".repeat(253);
    let run = typed(
        json!({ "M": [{ "name": name, "type": "string" }] }),
        object(&name, json!("x")),
    )
    .unwrap();
    let definition = run
        .apdus
        .iter()
        .find(|a| a[..4] == [0xe0, 0x1a, 0x00, 0xff] && a[4] == 255)
        .unwrap();
    assert_eq!(definition[5..7], [0x05, 253]);
    // One byte more is refused, as a name of 256 characters is.
    let name = "a".repeat(254);
    let refused = typed(
        json!({ "M": [{ "name": name, "type": "string" }] }),
        object(&name, json!("x")),
    );
    assert_eq!(
        refusal_of(refused),
        Refusal::TooLarge(Bound::Definition(256))
    );
    let name = "a".repeat(256);
    let refused = typed(
        json!({ "M": [{ "name": name, "type": "string" }] }),
        object(&name, json!("x")),
    );
    assert_eq!(refusal_of(refused), Refusal::TooLarge(Bound::Name(256)));
    // A primary type's name of 255 is sent, as its type and as its root.
    let primary = "P".repeat(255);
    let run = typed(
        object(&primary, json!([{ "name": "v", "type": "uint8" }])),
        json!({ "v": 1 }),
    )
    .unwrap();
    for header in [[0xe0, 0x1a, 0x00, 0x00], [0xe0, 0x1c, 0x00, 0x00]] {
        assert!(
            run.apdus
                .iter()
                .any(|a| a[..4] == header && a[4] == 255 && a[5..] == *primary.as_bytes())
        );
    }
    let primary = "P".repeat(256);
    let refused = typed(
        object(&primary, json!([{ "name": "v", "type": "uint8" }])),
        json!({ "v": 1 }),
    );
    assert_eq!(refusal_of(refused), Refusal::TooLarge(Bound::Name(256)));
    // A name outside 0002's identifiers is refused before any APDU.
    for name in ["é", "a😀", "a b"] {
        let refused = typed(
            json!({ "M": [{ "name": name, "type": "string" }] }),
            object(name, json!("x")),
        );
        assert!(
            matches!(refusal_of(refused), Refusal::TypedData(_)),
            "{name}"
        );
    }
}

#[test]
fn typed_data_must_hash_to_the_confirmed_hash() {
    let case = case("typed-mail");
    let typed = &case["request"]["typed_data"];
    let mut other = typed_hash(case);
    other[0] ^= 1;
    assert_eq!(
        refusal_of(typed_operation(account(&case["record"]), typed, &other)),
        Refusal::HashMismatch
    );
}

#[test]
fn discovery_reads_one_to_twenty_paths_in_the_schemes() {
    for count in [0, 21] {
        assert_eq!(
            refusal_of(Operation::accounts(Scheme::Live, 0, count)),
            Refusal::Count
        );
    }
    assert!(Operation::accounts(Scheme::Legacy, (1 << 31) - 20, 20).is_ok());
    assert!(matches!(
        refusal_of(Operation::accounts(Scheme::Legacy, (1 << 31) - 19, 20)),
        Refusal::Path(_)
    ));
    assert!(matches!(
        refusal_of(Operation::accounts(Scheme::Live, u64::MAX, 1)),
        Refusal::Path(_)
    ));
}

#[test]
fn a_written_form_the_device_wouldnt_rebuild_is_refused_before_any_apdu() {
    // M(uint8[02] v): the hash's encodeType keeps "[02]", the device
    // rebuilds "[2]" from the descriptor. Refused at the operation's
    // construction, so no APDU exists to send.
    for (ty, value) in [
        ("uint8[02]", json!([1, 2])),
        ("uint8[2][02]", json!([[1, 2], [3, 4]])),
        ("uint8[02][]", json!([[1, 2]])),
        ("uint8[00]", json!([])),
        ("uint[02]", json!([1, 2])),
    ] {
        let refused = typed(
            json!({ "M": [{ "name": "v", "type": ty }] }),
            json!({ "v": value }),
        );
        let refusal = refusal_of(refused);
        assert_eq!(refusal, Refusal::NotCanonical, "{ty}");
        assert_eq!(refusal.code(), Some(LedgerCode::TypeNotCanonical), "{ty}");
        assert_eq!(
            LedgerCode::TypeNotCanonical.as_str(),
            "LEDGER_TYPE_NOT_CANONICAL"
        );
    }
    // The canonical forms go through, the device's suffix in the descriptor.
    for (ty, value, dims) in [
        ("uint8[2]", json!([1, 2]), vec![1u8, 1, 2]),
        ("uint8[]", json!([1, 2, 3]), vec![1, 0]),
        ("uint8[0]", json!([]), vec![1, 1, 0]),
        ("uint8[2][]", json!([[1, 2]]), vec![2, 1, 2, 0]),
    ] {
        let run = typed(
            json!({ "M": [{ "name": "v", "type": ty }] }),
            json!({ "v": value }),
        )
        .unwrap();
        let mut descriptor = vec![0xc2, 0x01];
        descriptor.extend_from_slice(&dims);
        descriptor.extend_from_slice(&[1, b'v']);
        assert!(
            run.apdus
                .iter()
                .any(|a| a[..4] == [0xe0, 0x1a, 0x00, 0xff] && a[5..] == descriptor[..]),
            "{ty}"
        );
    }
}

#[test]
fn the_excluded_written_form_class_is_refused() {
    // ledger.json's typed_data_excluded names the one 0002 case no Ledger
    // case carries; every instance of it in signing.json, which the vault
    // signs as ethers does, is refused for a Ledger.
    let excluded = ledger()["typed_data_excluded"].as_array().unwrap();
    assert_eq!(excluded.len(), 1);
    assert_eq!(excluded[0]["id"], "array-suffix-written-form");
    let signing = load("signing.json");
    let mut refused = 0;
    for case in signing["typedData"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if !id.starts_with("array-suffix-written-form/") {
            continue;
        }
        assert_eq!(
            case["result"]["status"], "success",
            "{id}: the vault signs it"
        );
        let typed = &case["typed_data"];
        let hash: [u8; 32] = unhex(case["result"]["hash"].as_str().unwrap())
            .try_into()
            .unwrap();
        let refusal = refusal_of(typed_operation(account_at("44'/60'/0'/0/0"), typed, &hash));
        assert_eq!(refusal.code(), Some(LedgerCode::TypeNotCanonical), "{id}");
        refused += 1;
    }
    assert_eq!(refused, 3);
}
