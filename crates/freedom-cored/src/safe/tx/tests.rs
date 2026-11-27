//! What `safe.prepare` builds and keeps, and the vault owners' signatures
//! `safe.propose` makes, alone (the requests are `methods`' tests).

use fc_evm::{checksum_address, recover_address};
use fc_wallet_state::vault_meta::VaultMeta;

use super::*;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// `abandon … about`'s accounts 0 to 2 (keys.json).
const A: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const B: &str = "0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265";
const C: &str = "0x07B5FdfEB4E11826D233403Fe8Db0611CCF4c231";
const LEDGER: &str = "0x58A57ed9d8d624cBD12e2C467D34787555bB1b25";

fn address(text: &str) -> [u8; 20] {
    parse_address(text).unwrap()
}

fn unlocked() -> VaultState {
    let mut state = VaultState::new();
    let ticket = state.ticket();
    let prepared = fc_vault::state::Prepared::new(fc_keys::Mnemonic::parse(ABANDON).unwrap());
    state.install(ticket, prepared, 0, 0).unwrap();
    state
}

/// Three vault accounts and a Ledger, with `wrong`'s record at index 1
/// holding another address than its key's.
fn records(wrong: bool) -> Records {
    let meta = serde_json::json!({
        "userKnowsPassword": true,
        "addresses": { "userWallet": A, "beeWallet": B },
        "derivedWallets": [
            { "index": 0, "name": "Wallet 1", "address": A },
            { "index": 1, "name": "Wallet 2", "address": if wrong { C } else { B } },
            { "index": 2, "name": "Wallet 3", "address": C },
            { "index": 1_000_000, "name": "Ledger 1", "address": LEDGER, "type": "ledger",
              "path": "m/44'/60'/0'/0/0", "addressCheck": "matched" },
        ],
        "activeWalletIndex": 0,
        "nextHardwareWalletIndex": 1_000_001,
    });
    Records::Read(VaultMeta::load(meta.to_string().as_bytes()).unwrap())
}

#[test]
fn a_call_is_three_strings() {
    let to = "0x3434343434343434343434343434343434343434";
    let call = Call::of(&json!({ "to": to, "value": "0x10", "data": "0xABcd" })).unwrap();
    assert_eq!(
        call,
        Call {
            to: address(to),
            value: U256::from_u64(16),
            data: vec![0xab, 0xcd],
        }
    );
    assert_eq!(
        Call::of(&json!({ "to": to, "value": "16", "data": "0x" }))
            .unwrap()
            .value,
        U256::from_u64(16)
    );
    for bad in [
        json!({ "to": to, "value": "1" }),
        json!({ "to": to, "value": "1", "data": "0x", "operation": 1 }),
        json!({ "to": to, "value": 1, "data": "0x" }),
        json!({ "to": to, "value": "-1", "data": "0x" }),
        json!({ "to": to, "value": "1", "data": "abcd" }),
        json!({ "to": "0x3434", "value": "1", "data": "0x" }),
        // A mixed-case address must carry its checksum.
        json!({ "to": "0x3434343434343434343434343434343434343434".replace("0x34", "0xAb"), "value": "1", "data": "0x" }),
        json!([to, "1", "0x"]),
    ] {
        assert_eq!(
            Call::of(&bad).unwrap_err().code,
            ErrorCode::InvalidArgument,
            "{bad}"
        );
    }
    // Data past 64 KiB is refused before any read.
    let long = to_hex(&vec![0; fc_safe::MAX_DATA + 1]);
    assert!(Call::of(&json!({ "to": to, "value": "1", "data": long })).is_err());
    let most = to_hex(&vec![0; fc_safe::MAX_DATA]);
    assert!(Call::of(&json!({ "to": to, "value": "1", "data": most })).is_ok());
    // Data past 64 KiB, and a nonce past 2^53 − 1, build no SafeTx.
    let mut call = call;
    call.data = vec![0; fc_safe::MAX_DATA + 1];
    assert!(call.at(&U256::from_u64(1)).is_err());
    call.data = vec![0; fc_safe::MAX_DATA];
    assert!(call.at(&U256::from_u64(fc_safe::MAX_NONCE)).is_ok());
    assert!(call.at(&U256::from_u64(fc_safe::MAX_NONCE + 1)).is_err());
}

#[test]
fn a_call_to_the_safe_itself_is_refused() {
    let safe = [0x5a; 20];
    let call = Call {
        to: safe,
        value: U256::ZERO,
        data: vec![],
    };
    let refused = call.check_not_self(&safe).unwrap_err();
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert_eq!(refused.message, SELF_CALL_TEXT);
    assert_eq!(refused.data, Some(json!({ "safe": "self_call" })));
    assert!(call.check_not_self(&[0x5b; 20]).is_ok());
}

fn prepared(index: u64, nonce: u64) -> Prepared {
    let tx = SafeTx::new([0x33; 20], U256::from_u64(5), vec![0xab], nonce).unwrap();
    Prepared::new(index, [0x5a; 20], tx).unwrap()
}

#[test]
fn the_answer_is_the_fields_their_hash_and_the_view() {
    let prepared = prepared(7, 3);
    let answer = prepared.answer().unwrap();
    assert_eq!(answer["safe_tx"], prepared.tx.fields());
    assert_eq!(answer["safe_tx_hash"], to_hex(&prepared.hash));
    assert_eq!(prepared.hash, prepared.tx.hash(&[0x5a; 20]).unwrap());
    let view = &answer["view"];
    assert_eq!(view["primary_type"], "SafeTx");
    assert_eq!(view["named_type"], "match");
    assert_eq!(view["chain"], "match");
    assert_eq!(view["message"]["nonce"], "3");
    // The token's payload is the same SafeTx.
    let payload = prepared.token_payload();
    assert_eq!(payload["safe_tx"], prepared.tx.fields());
    assert_eq!(payload["safe_tx_hash"], answer["safe_tx_hash"]);
    assert_eq!(payload["chain_id"], "100");
    assert_eq!(payload["safe"], checksum_address(&[0x5a; 20]));
}

#[test]
fn at_most_the_bound_is_kept_the_oldest_dropped() {
    let mut kept = PreparedTxs::default();
    for nonce in 0..MAX_PREPARED as u64 + 3 {
        kept.keep(prepared(7, nonce));
    }
    assert_eq!(kept.len(), MAX_PREPARED);
    let first = prepared(7, 0);
    assert!(kept.get(7, &first.safe, &first.hash).is_none());
    let last = prepared(7, MAX_PREPARED as u64 + 2);
    assert!(kept.get(7, &last.safe, &last.hash).is_some());
    // The same SafeTx again is kept once; another Safe's index finds none.
    kept.keep(last.clone());
    assert_eq!(kept.len(), MAX_PREPARED);
    assert!(kept.get(8, &last.safe, &last.hash).is_none());
    assert_eq!(kept.take(7, &last.safe, &last.hash), Some(last.clone()));
    assert!(kept.take(7, &last.safe, &last.hash).is_none());
    assert_eq!(kept.len(), MAX_PREPARED - 1);
}

#[test]
fn the_vault_owners_sign_in_order_until_the_threshold() {
    let state = unlocked();
    let hash = [0x42; 32];
    let all = [address(A), address(B), address(C)];
    let vault = [(0, address(A)), (1, address(B)), (2, address(C))];
    let signers = |state: &VaultState, records: &Records, vault: &[(u64, [u8; 20])], threshold| {
        vault_signatures(state, records, vault, &all, &hash, threshold)
            .iter()
            .map(|signature| {
                // Each over the hash, recovered to its owner.
                assert_eq!(
                    recover_address(&hash, signature.signature()).unwrap(),
                    *signature.owner()
                );
                *signature.owner()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(signers(&state, &records(false), &vault, 1), [address(A)]);
    assert_eq!(
        signers(&state, &records(false), &vault, 2),
        [address(A), address(B)]
    );
    // In the record's order, whatever the addresses' order.
    assert_eq!(
        signers(&state, &records(false), &[vault[2], vault[0]], 2),
        [address(C), address(A)]
    );
    // A record whose address isn't its key's is passed over, and the next
    // owner signs.
    assert_eq!(
        signers(&state, &records(true), &[(1, address(C)), vault[0]], 1),
        [address(A)]
    );
    // An index the vault doesn't sign for (a Ledger's) is passed over.
    assert_eq!(
        signers(
            &state,
            &records(false),
            &[(1_000_000, address(LEDGER)), vault[1]],
            1
        ),
        [address(B)]
    );
    // An owner not in the Safe's list signs nothing that counts.
    assert!(vault_signatures(&state, &records(false), &vault[..1], &all[1..], &hash, 2).is_empty());
    // Locked: none.
    assert!(signers(&VaultState::new(), &records(false), &vault, 2).is_empty());
}
