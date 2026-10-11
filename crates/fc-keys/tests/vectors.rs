//! Checks fc-keys against the golden vectors generated from freedom-browser's
//! JS (`vectors/`). Set `FC_VECTORS_DIR` to use another checkout's vectors.

// Test helpers outside #[test] functions; panicking on bad fixtures is intended.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_keys::freedom::{self, derive_publisher, derive_user_wallet};
use fc_keys::{Ed25519Key, Error, Mnemonic, Secp256k1Key, is_valid_mnemonic};
use serde_json::Value;

const INDICES: [u32; 5] = [0, 1, 2, 1000, 2_147_483_647];

fn load(name: &str) -> Value {
    let dir = std::env::var_os("FC_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors"));
    let text = std::fs::read_to_string(dir.join(name)).unwrap();
    // A lone surrogate can't exist in a Rust string, and the core's JSON
    // decoder rejects it; the vector expects `valid: false` for it anyway.
    let text = text.replace("\\ud800", "<lone-surrogate>");
    serde_json::from_str(&text).unwrap()
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing {key} in {value}"))
}

fn check_secp(expected: &Value, key: &Secp256k1Key) {
    assert_eq!(key.path().to_string(), str_of(expected, "path"));
    assert_eq!(
        format!("0x{}", hex::encode(key.to_secret_bytes().as_slice())),
        str_of(expected, "privateKey")
    );
    assert_eq!(
        format!("0x{}", hex::encode(key.public_key())),
        str_of(expected, "publicKey")
    );
    assert_eq!(key.address().to_string(), str_of(expected, "address"));
}

fn check_ed25519(expected: &Value, key: &Ed25519Key) {
    assert_eq!(key.path().to_string(), str_of(expected, "path"));
    assert_eq!(
        hex::encode(key.to_secret_bytes().as_slice()),
        str_of(expected, "privateKey")
    );
    assert_eq!(hex::encode(key.public_key()), str_of(expected, "publicKey"));
}

#[test]
fn keys_json() {
    let file = load("keys.json");
    let vectors = file["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 6);
    for vector in vectors {
        let id = str_of(vector, "id");
        let seed = Mnemonic::parse(str_of(vector, "mnemonic"))
            .unwrap()
            .to_seed();
        assert_eq!(
            hex::encode(seed.as_bytes()),
            str_of(vector, "seed"),
            "{id} seed"
        );

        for (expected, index) in vector["userWallets"]
            .as_array()
            .unwrap()
            .iter()
            .zip(INDICES)
        {
            check_secp(expected, &derive_user_wallet(&seed, index).unwrap());
            assert_eq!(expected["accountIndex"], index, "{id} account {index}");
        }
        for (expected, index) in vector["publisherKeys"]
            .as_array()
            .unwrap()
            .iter()
            .zip(INDICES)
        {
            check_secp(expected, &derive_publisher(&seed, index).unwrap());
            assert_eq!(expected["originIndex"], index, "{id} origin {index}");
        }
        let all = freedom::derive_all(&seed).unwrap();
        check_secp(&vector["beeWallet"], &all.bee_wallet);
        check_ed25519(&vector["radicleKey"], &all.radicle);
        check_ed25519(&vector["ipfsKey"], &all.ipfs);
        check_secp(&vector["userWallets"][0], &all.user_wallet);
    }
}

#[test]
fn index_above_max_is_rejected_like_ethers() {
    let file = load("keys.json");
    for entry in file["edgeCases"].as_array().unwrap() {
        let case = entry["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "max-plus-one")
            .unwrap();
        // JS throws for both; integer-typing errors are the protocol layer's job.
        assert_eq!(case["userWallet"]["status"], "error");
        assert_eq!(case["publisherKey"]["status"], "error");
        assert_eq!(
            freedom::user_wallet_path(1 << 31).unwrap_err(),
            Error::IndexOutOfRange(1 << 31)
        );
        assert_eq!(
            freedom::publisher_path(1 << 31).unwrap_err(),
            Error::IndexOutOfRange(1 << 31)
        );
    }
}

#[test]
fn mnemonic_validation_json() {
    let file = load("mnemonic-validation.json");
    let mut checked = 0;
    for vector in file["vectors"].as_array().unwrap() {
        let id = str_of(vector, "id");
        let Some(input) = vector["input"].as_str() else {
            // Non-string inputs are rejected by the protocol's typed params.
            assert_eq!(vector["valid"], false, "{id}");
            continue;
        };
        let valid = vector["valid"].as_bool().unwrap();
        assert_eq!(is_valid_mnemonic(input), valid, "{id}: {input:?}");
        let seed = &vector["getSeed"];
        if valid {
            let rust = hex::encode(Mnemonic::parse(input).unwrap().to_seed().as_bytes());
            assert_eq!(seed["status"], "success", "{id}");
            assert_eq!(rust, str_of(seed, "value"), "{id} seed");
            let wallet = &vector["userWallet0"];
            assert_eq!(wallet["status"], "success", "{id}");
            let seed = Mnemonic::parse(input).unwrap().to_seed();
            check_secp(&wallet["value"], &derive_user_wallet(&seed, 0).unwrap());
        } else {
            assert_eq!(seed["status"], "error", "{id}");
        }
        checked += 1;
    }
    assert!(checked >= 25, "only {checked} string vectors checked");
}
