//! fc-ledger's reading of a Ledger's answers (design 0016, "Answers the
//! core checks"): every reply main relays from the device, for each kind
//! of operation. The answers come from a USB device.
//!
//! The first byte picks the operation (vectors/ledger.json's
//! `discovery-live-0-2`, `add-live-0`, `msg-live-1`,
//! `tx-type0-chain-1-parity-0`, `tx-type2-chain-1-parity-0` and
//! `typed-mail`, under abandon-12's first live account). The rest is the
//! replies, each a tag (bit 0: `hash_only: "shown"`; bits 1–2: an answer,
//! one of main's failures, or a refusal), a 2-byte length and that many
//! bytes. It checks, besides panics, that a signature it returns recovers
//! to the account over the operation's digest, and a transaction's sender
//! is the account.

#![no_main]

use fc_evm::{Transaction, decode_signed, eip191_digest, parse_address, recover_address};
use fc_ledger::{Account, Failed, LedgerPath, Operation, Reply, Scheme, Signed, Step};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

const ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const MAIL_HASH: &str = "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";

fn account() -> Account {
    Account {
        path: LedgerPath::parse("44'/60'/0'/0/0").unwrap(),
        address: parse_address(ADDRESS).unwrap(),
    }
}

fn mail_hash() -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&MAIL_HASH[2 * i..2 * i + 2], 16).unwrap();
    }
    hash
}

fn operation(kind: u8) -> Operation {
    let tx = |fields: serde_json::Value| {
        Operation::sign_transaction(account(), &Transaction::from_json(&fields).unwrap()).unwrap()
    };
    match kind % 6 {
        0 => Operation::accounts(Scheme::Live, 0, 2).unwrap(),
        1 => Operation::add(LedgerPath::new(Scheme::Live, 0).unwrap()),
        2 => Operation::sign_message(account(), vec![0x03]).unwrap(),
        3 => tx(json!({
            "type": 0, "chain_id": "1", "nonce": "0", "gas_limit": "21000",
            "to": "0x8ba1f109551bD432803012645Ac136ddd64DBA72", "value": "1000000000000000",
            "data": "0x", "gas_price": "1000000000"
        })),
        4 => tx(json!({
            "type": 2, "chain_id": "1", "nonce": "2", "gas_limit": "21000",
            "to": "0x8ba1f109551bD432803012645Ac136ddd64DBA72", "value": "1000000000000000",
            "data": "0x", "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000"
        })),
        _ => Operation::sign_typed_data(
            account(),
            &json!({
                "name": "Ether Mail", "version": "1", "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            }),
            &json!({
                "Person": [{ "name": "name", "type": "string" }, { "name": "wallet", "type": "address" }],
                "Mail": [
                    { "name": "from", "type": "Person" }, { "name": "to", "type": "Person" },
                    { "name": "contents", "type": "string" }
                ]
            }),
            &json!({
                "from": { "name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
                "to": { "name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
                "contents": "Hello, Bob!"
            }),
            &mail_hash(),
        )
        .unwrap(),
    }
}

const FAILED: [Failed; 5] = [
    Failed::NotFound,
    Failed::Busy,
    Failed::Disconnected,
    Failed::Unresponsive,
    Failed::Timeout,
];

fuzz_target!(|data: &[u8]| {
    let Some((kind, mut rest)) = data.split_first() else {
        return;
    };
    let mut op = operation(*kind);
    let mut step = op.start();
    let done = loop {
        let exchange = match step {
            Step::Send(exchange) => exchange,
            Step::Done(done) => break done,
        };
        assert!(exchange.apdu.as_bytes().len() <= 260);
        let Some((head, after)) = rest.split_first_chunk::<3>() else {
            return;
        };
        let len = usize::from(u16::from_be_bytes([head[1], head[2]]));
        let (bytes, after) = after.split_at(len.min(after.len()));
        rest = after;
        let reply = match (head[0] >> 1) % 4 {
            1 => Reply::Failed(FAILED[len % FAILED.len()]),
            2 => Reply::Refused,
            _ => Reply::Answer {
                answer: bytes,
                hash_only_shown: head[0] & 1 == 1,
            },
        };
        step = op.answer(reply);
    };
    let address = account().address;
    match done {
        Ok(Signed::Transaction(tx)) => {
            assert_eq!(decode_signed(&tx.raw).unwrap().signer(), Some(address));
        }
        Ok(Signed::Signature(signature)) => {
            let digest = if kind % 6 == 2 {
                eip191_digest(&[0x03])
            } else {
                mail_hash()
            };
            assert_eq!(recover_address(&digest, &signature), Ok(address));
        }
        Ok(Signed::Accounts(accounts)) => assert!(kind % 6 == 0 && accounts.len() == 2),
        Ok(Signed::Added(_)) => assert_eq!(kind % 6, 1),
        Err(_) => {}
    }
});
