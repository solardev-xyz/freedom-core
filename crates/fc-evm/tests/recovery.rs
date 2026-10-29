//! recover_address against the single-owner chunks in vectors/signing.json,
//! which bee-js signed (design 0002): each recovers its recorded owner.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_evm::{eip191_digest, keccak256, parse_address, parse_bytes, recover_address};

#[test]
fn every_signed_chunk_recovers_its_owner() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/signing.json");
    let vectors: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut recovered = 0;
    for case in vectors["socs"].as_array().unwrap() {
        let result = &case["result"];
        if result["status"] != "success" {
            continue;
        }
        let id = parse_bytes(case["identifier"].as_str().unwrap(), "identifier").unwrap();
        let chunk = parse_bytes(result["chunkAddress"].as_str().unwrap(), "chunk address").unwrap();
        let signature: [u8; 65] = parse_bytes(result["signature"].as_str().unwrap(), "signature")
            .unwrap()
            .try_into()
            .unwrap();
        // Bee signs the EIP-191 digest of keccak256(id ‖ chunk address).
        let digest = eip191_digest(&keccak256(&[id, chunk].concat()));
        let owner = parse_address(result["owner"].as_str().unwrap()).unwrap();
        assert_eq!(
            recover_address(&digest, &signature),
            Ok(owner),
            "{}",
            case["id"]
        );
        recovered += 1;
    }
    assert!(recovered >= 40, "only {recovered} chunks checked");
}

/// `r ‖ s ‖ v` from two scalars, big-endian.
fn signature(r: &[u8; 32], s: &[u8; 32], v: u8) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(r);
    out[32..64].copy_from_slice(s);
    out[64] = v;
    out
}

fn scalar(hex: &str) -> [u8; 32] {
    parse_bytes(hex, "scalar").unwrap().try_into().unwrap()
}

fn small(n: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = n;
    out
}

/// secp256k1's group order.
const N: &str = "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
/// The base point's x-coordinate.
const G_X: &str = "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// v = 29 and 30 name an r reduced mod the order (R.x = r + n). With the
/// zero digest, r = 2 and s = 1, both points exist; the addresses are an
/// independent implementation's (noble-curves' recoverPublicKey, then
/// keccak256 of the uncompressed point).
#[test]
fn extended_recovery_ids_recover() {
    for (v, address) in [
        (29u8, "0x5cbe0610f39fdead804d3fa62af6c26a14178398"),
        (30, "0x7eb0740f7d357d394998ce41160eb27c2818d499"),
    ] {
        assert_eq!(
            recover_address(&[0u8; 32], &signature(&small(2), &small(1), v)),
            Ok(parse_address(address).unwrap()),
            "v = {v}"
        );
    }
}

#[test]
fn scalar_boundaries_are_refused() {
    let digest = keccak256(b"a digest");
    let order = scalar(N);
    for (what, r, s) in [
        ("zero s", small(2), [0u8; 32]),
        ("r equal to the order", order, small(1)),
        ("s equal to the order", small(2), order),
    ] {
        for v in 27u8..=30 {
            assert_eq!(
                recover_address(&digest, &signature(&r, &s, v)),
                Err(fc_evm::Error::Recovery),
                "{what}, v = {v}"
            );
        }
    }
}

/// Digest 1, r = G.x, s = 1, v = 27: R = G, so the key r⁻¹(s·R − e·G) is
/// the point at infinity, which is no key.
#[test]
fn the_point_at_infinity_is_refused() {
    assert_eq!(
        recover_address(&small(1), &signature(&scalar(G_X), &small(1), 27)),
        Err(fc_evm::Error::Recovery)
    );
}
