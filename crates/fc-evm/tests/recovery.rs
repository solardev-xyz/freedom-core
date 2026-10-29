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
