//! Checks the identity encoders against the golden vectors from
//! freedom-browser's JS (`vectors/`). Set `FC_VECTORS_DIR` to override.

// Test helpers outside #[test] functions; panicking on bad fixtures is intended.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::PathBuf;

use fc_keys::keystore::{self, KeystoreParams};
use fc_keys::{Error, Mnemonic, Seed, freedom, multiformats, openssh};
use serde_json::Value;

fn load(name: &str) -> Value {
    let dir = std::env::var_os("FC_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors"));
    serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap()
}

fn seeds() -> HashMap<String, Seed> {
    load("keys.json")["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let id = v["id"].as_str().unwrap().to_owned();
            (
                id,
                Mnemonic::parse(v["mnemonic"].as_str().unwrap())
                    .unwrap()
                    .to_seed(),
            )
        })
        .collect()
}

fn s(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value}"))
}

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

#[test]
fn identity_formats() {
    let seeds = seeds();
    let file = load("identity-formats.json");
    let vectors = file["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 6);
    for vector in vectors {
        let keys = freedom::derive_all(&seeds[s(&vector["mnemonicId"])]).unwrap();
        assert_eq!(
            *multiformats::ipfs_private_key(&keys.ipfs),
            s(&vector["ipfs"]["privKey"])
        );
        assert_eq!(
            multiformats::ipfs_peer_id(&keys.ipfs.public_key()),
            s(&vector["ipfs"]["peerId"])
        );
        let radicle = keys.radicle.public_key();
        assert_eq!(
            multiformats::did_key(&radicle),
            s(&vector["didFromPublicKey"])
        );
        for entry in vector["radicle"].as_array().unwrap() {
            assert_eq!(multiformats::did_key(&radicle), s(&entry["did"]));
            assert_eq!(multiformats::radicle_node_id(&radicle), s(&entry["nodeId"]));
            assert_eq!(
                openssh::public_key_line(&radicle, s(&entry["comment"])),
                s(&entry["publicKeyFile"])
            );
        }
    }
}

#[test]
fn radicle_openssh_files_are_byte_identical() {
    let seeds = seeds();
    let file = load("fixtures/radicle-openssh.json");
    let fixtures = file["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 12);
    for fixture in fixtures {
        let keys = freedom::derive_all(&seeds[s(&fixture["mnemonicId"])]).unwrap();
        let check = u32::from_be_bytes(bytes::<4>(s(&fixture["checkIntegerHex"])));
        let comment = s(&fixture["comment"]);
        let file = openssh::private_key_file_with_check(&keys.radicle, comment, check);
        assert_eq!(
            *file,
            s(&fixture["identity"]["privateKeyFile"]),
            "{fixture}"
        );
        assert_eq!(
            openssh::public_key_line(&keys.radicle.public_key(), comment),
            s(&fixture["identity"]["publicKeyFile"])
        );
    }
}

#[test]
fn bee_keystores() {
    let seeds = seeds();
    let file = load("fixtures/bee-keystores.json");
    let fixtures = file["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 2);
    for fixture in fixtures {
        let json = s(&fixture["keystore"]);
        let password = s(&fixture["password"]);

        // Rust decrypts what ethers wrote.
        let decrypted = keystore::decrypt(json, password).unwrap();
        assert_eq!(decrypted.address().to_string(), s(&fixture["address"]));
        assert_eq!(
            format!("0x{}", hex::encode(decrypted.to_secret_bytes().as_slice())),
            s(&fixture["privateKey"])
        );
        assert_eq!(
            keystore::decrypt(json, "wrong password").unwrap_err(),
            Error::IncorrectPassword
        );
        if let Some(nfd) = fixture["nfdPasswordOutcome"].as_object() {
            // ethers normalizes keystore passwords with NFKC.
            let via_nfd = keystore::decrypt(json, nfd["password"].as_str().unwrap()).unwrap();
            assert_eq!(via_nfd.address(), decrypted.address());
        }

        // Rust reproduces ethers' keystore byte for byte from the same inputs.
        let parsed = &fixture["parsed"];
        let params = KeystoreParams {
            salt: bytes(s(&parsed["Crypto"]["kdfparams"]["salt"])),
            iv: bytes(s(&parsed["Crypto"]["cipherparams"]["iv"])),
            uuid: bytes(&s(&parsed["id"]).replace('-', "")),
        };
        let bee = freedom::derive_all(&seeds[s(&fixture["mnemonicId"])])
            .unwrap()
            .bee_wallet;
        assert_eq!(keystore::encrypt(&bee, password, &params).unwrap(), json);
    }
}
