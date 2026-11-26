//! The chain-generic SafeTx and SafeMessage hashes and `execTransaction`'s
//! calldata (design 0016, SAFE-2's D5), against the private copies
//! fc-approval kept before it hashed through fc-safe, which are reproduced
//! here as they were: one encoding, so every binding `approvals.json` and
//! `safe.json` pin, chain 1's included, hashes as it did.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_evm::{U256, keccak256, to_hex, typed_data_hash};
use fc_safe::constants::CHAIN_ID;
use fc_safe::{
    EXEC_TRANSACTION_SELECTOR, MAX_NONCE, SafeMessage, SafeTx, exec_call, exec_transaction,
    safe_message_hash, safe_message_typed_data, safe_tx_hash, safe_tx_typed_data,
};
use serde_json::{Value, json};

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// fc-approval's `safe_tx_hash` before D5.
fn before_safe_tx_hash(
    safe: &[u8; 20],
    chain_id: &U256,
    to: &[u8; 20],
    value: &U256,
    data: &[u8],
    nonce: &U256,
) -> Option<[u8; 32]> {
    let field = |name: &str, kind: &str| json!({ "name": name, "type": kind });
    let types = json!({
        "SafeTx": [
            field("to", "address"),
            field("value", "uint256"),
            field("data", "bytes"),
            field("operation", "uint8"),
            field("safeTxGas", "uint256"),
            field("baseGas", "uint256"),
            field("gasPrice", "uint256"),
            field("gasToken", "address"),
            field("refundReceiver", "address"),
            field("nonce", "uint256"),
        ],
    });
    let domain = json!({ "chainId": chain_id.to_decimal(), "verifyingContract": to_hex(safe) });
    let message = json!({
        "to": to_hex(to),
        "value": value.to_decimal(),
        "data": to_hex(data),
        "operation": "0",
        "safeTxGas": "0",
        "baseGas": "0",
        "gasPrice": "0",
        "gasToken": ZERO_ADDRESS,
        "refundReceiver": ZERO_ADDRESS,
        "nonce": nonce.to_decimal(),
    });
    typed_data_hash(&domain, &types, &message).ok()
}

/// fc-approval's `safe_message_hash` before D5.
fn before_safe_message_hash(
    safe: &[u8; 20],
    chain_id: &U256,
    digest: &[u8; 32],
) -> Option<[u8; 32]> {
    let types = json!({ "SafeMessage": [{ "name": "message", "type": "bytes" }] });
    let domain = json!({ "chainId": chain_id.to_decimal(), "verifyingContract": to_hex(safe) });
    let message = json!({ "message": to_hex(digest) });
    typed_data_hash(&domain, &types, &message).ok()
}

fn word(bytes: &[u8]) -> [u8; 32] {
    let mut word = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    word[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    word
}

fn padded(len: usize) -> usize {
    len.div_ceil(32).saturating_mul(32)
}

/// fc-approval's `exec_call` before D5.
fn before_exec_call(to: &[u8; 20], value: &U256, data: &[u8], signatures: &[u8]) -> Vec<u8> {
    let head = 10 * 32;
    let data_offset = head;
    let signatures_offset = head + 32 + padded(data.len());
    let mut call = Vec::with_capacity(4 + signatures_offset + 32 + padded(signatures.len()));
    call.extend_from_slice(&before_exec_selector());
    call.extend_from_slice(&word(to));
    call.extend_from_slice(&value.to_be_bytes());
    call.extend_from_slice(&word(&(data_offset as u64).to_be_bytes()));
    call.extend_from_slice(&[0u8; 6 * 32]);
    call.extend_from_slice(&word(&(signatures_offset as u64).to_be_bytes()));
    for bytes in [data, signatures] {
        call.extend_from_slice(&word(&(bytes.len() as u64).to_be_bytes()));
        call.extend_from_slice(bytes);
        call.resize(call.len() + padded(bytes.len()) - bytes.len(), 0);
    }
    call
}

/// fc-approval's `exec_selector` before D5.
fn before_exec_selector() -> [u8; 4] {
    let hash = keccak256(
        b"execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    );
    [hash[0], hash[1], hash[2], hash[3]]
}

/// The chains a `safe-send` or `safe-message` binding allows, at their
/// edges (1 to 2^53 − 1), and Gnosis.
const CHAINS: [u64; 5] = [1, 10, CHAIN_ID, 137, MAX_NONCE];

fn nonces() -> Vec<U256> {
    let mut past_u64 = [0u8; 32];
    past_u64[23] = 1;
    vec![
        U256::ZERO,
        U256::from_u64(7),
        U256::from_u64(MAX_NONCE),
        U256::from_u64(MAX_NONCE + 1),
        U256::from_u64(u64::MAX),
        U256::from_be_slice(&past_u64).unwrap(),
        U256::MAX,
    ]
}

#[test]
fn the_safe_tx_hash_is_fc_approvals_on_every_chain() {
    let safe = [0x11; 20];
    let to = [0x83; 20];
    let mut checked = 0;
    for chain_id in CHAINS {
        for nonce in nonces() {
            for value in [U256::ZERO, U256::from_u64(1000), U256::MAX] {
                for data in [vec![], vec![0xa9, 0x05, 0x9c, 0xbb], vec![0x5a; 33]] {
                    assert_eq!(
                        Some(safe_tx_hash(chain_id, &safe, &to, &value, &data, &nonce).unwrap()),
                        before_safe_tx_hash(
                            &safe,
                            &U256::from_u64(chain_id),
                            &to,
                            &value,
                            &data,
                            &nonce
                        ),
                        "chain {chain_id}, nonce {}",
                        nonce.to_decimal()
                    );
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 5 * 7 * 3 * 3);
    // Data past SafeTx's bound, as an approval may bind it.
    let long = vec![0xcd; fc_safe::MAX_DATA + 1];
    assert_eq!(
        Some(safe_tx_hash(1, &safe, &to, &U256::ZERO, &long, &U256::ZERO).unwrap()),
        before_safe_tx_hash(
            &safe,
            &U256::from_u64(1),
            &to,
            &U256::ZERO,
            &long,
            &U256::ZERO
        )
    );
}

#[test]
fn the_safe_message_hash_is_fc_approvals_on_every_chain() {
    let safe = [0x22; 20];
    for chain_id in CHAINS {
        for digest in [[0u8; 32], keccak256(b"hello"), [0xff; 32]] {
            assert_eq!(
                Some(safe_message_hash(chain_id, &safe, &digest).unwrap()),
                before_safe_message_hash(&safe, &U256::from_u64(chain_id), &digest),
                "chain {chain_id}"
            );
        }
    }
}

#[test]
fn exec_call_is_fc_approvals() {
    assert_eq!(EXEC_TRANSACTION_SELECTOR, before_exec_selector());
    let to = [0x83; 20];
    for value in [U256::ZERO, U256::from_u64(1000), U256::MAX] {
        for data_len in [0, 1, 4, 31, 32, 33, 64, 65, 1000, fc_safe::MAX_DATA + 1] {
            for signatures_len in [0, 65, 130, 195] {
                let data: Vec<u8> = (0..data_len).map(|i| i as u8).collect();
                let signatures = vec![0x5a; signatures_len];
                assert_eq!(
                    exec_call(&to, &value, &data, &signatures),
                    before_exec_call(&to, &value, &data, &signatures),
                    "data {data_len}, signatures {signatures_len}"
                );
            }
        }
    }
}

/// On Gnosis, the generic forms are SafeTx's and SafeMessage's own, text
/// for text.
#[test]
fn on_gnosis_they_are_the_safes_own() {
    let safe = [0x33; 20];
    let text = |value: &Value| serde_json::to_string(value).unwrap();
    for nonce in [0, 7, MAX_NONCE] {
        let tx = SafeTx::new([0x44; 20], U256::from_u64(5), vec![0xab, 0xcd], nonce).unwrap();
        let generic = safe_tx_typed_data(
            CHAIN_ID,
            &safe,
            tx.to(),
            tx.value(),
            tx.data(),
            &U256::from_u64(nonce),
        );
        assert_eq!(text(&generic), text(&tx.typed_data(&safe)));
        assert_eq!(generic["message"]["nonce"], json!(nonce));
        assert_eq!(
            safe_tx_hash(
                CHAIN_ID,
                &safe,
                tx.to(),
                tx.value(),
                tx.data(),
                &U256::from_u64(nonce)
            ),
            tx.hash(&safe)
        );
        assert_eq!(
            exec_call(tx.to(), tx.value(), tx.data(), &[1; 65]),
            exec_transaction(&tx, &[1; 65])
        );
    }
    let message = SafeMessage::personal_sign(b"hello");
    assert_eq!(
        text(&safe_message_typed_data(CHAIN_ID, &safe, message.digest())),
        text(&message.typed_data(&safe))
    );
    assert_eq!(
        safe_message_hash(CHAIN_ID, &safe, message.digest()),
        message.hash(&safe)
    );
}

/// A number JavaScript can't hold exactly goes as decimal text, which the
/// typed-data hash reads alike.
#[test]
fn wide_numbers_are_text() {
    let typed = safe_tx_typed_data(
        MAX_NONCE,
        &[1; 20],
        &[2; 20],
        &U256::ZERO,
        &[],
        &U256::from_u64(MAX_NONCE + 1),
    );
    assert_eq!(typed["domain"]["chainId"], json!(MAX_NONCE));
    assert_eq!(typed["message"]["nonce"], json!("9007199254740992"));
    let typed = safe_message_typed_data(u64::MAX, &[1; 20], &[0; 32]);
    assert_eq!(typed["domain"]["chainId"], json!("18446744073709551615"));
}
