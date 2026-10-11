//! Checks fc-vault against the vault fixtures generated from freedom-browser's
//! JS (`vectors/fixtures/vaults.json`).

// Test helpers outside #[test] functions; panicking on bad fixtures is intended.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fc_keys::Mnemonic;
use fc_vault::Error;
use fc_vault::format::{self, SealParams};
use serde_json::Value;

fn load() -> Value {
    let dir = std::env::var_os("FC_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors"));
    serde_json::from_str(&std::fs::read_to_string(dir.join("fixtures/vaults.json")).unwrap())
        .unwrap()
}

fn s(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value}"))
}

fn b64<const N: usize>(value: &Value) -> [u8; N] {
    STANDARD.decode(s(value)).unwrap().try_into().unwrap()
}

#[test]
fn opens_every_fixture_and_rejects_every_negative_case() {
    let file = load();
    let fixtures = file["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 5);
    for fixture in fixtures {
        let id = s(&fixture["id"]);
        let password = s(&fixture["password"]).as_bytes();
        let opened = format::open(s(&fixture["fileContents"]), password).unwrap();
        assert_eq!(opened.mnemonic.phrase(), s(&fixture["mnemonic"]), "{id}");
        assert_eq!(opened.iterations, 900_000, "{id}");

        let negatives = fixture["negativeCases"].as_array().unwrap();
        assert!(negatives.len() >= 6, "{id}");
        for negative in negatives {
            let case = s(&negative["id"]);
            // Every JS negative outcome is "Incorrect password".
            assert_eq!(
                s(&negative["outcome"]["message"]),
                "Incorrect password",
                "{id}/{case}"
            );
            assert_eq!(
                format::open(
                    s(&negative["fileContents"]),
                    s(&negative["password"]).as_bytes()
                )
                .unwrap_err(),
                Error::IncorrectPassword,
                "{id}/{case}"
            );
        }
    }
}

#[test]
fn reproduces_every_fixture_byte_for_byte() {
    let file = load();
    for fixture in file["fixtures"].as_array().unwrap() {
        let contents = s(&fixture["fileContents"]);
        let outer: Value = serde_json::from_str(contents).unwrap();
        let payload = &fixture["payload"];
        let params = SealParams {
            salt: b64(&payload["salt"]),
            iv: b64(&payload["iv"]),
            iterations: 900_000,
            created_at: s(&outer["createdAt"]).to_owned(),
        };
        let mnemonic = Mnemonic::parse(s(&fixture["mnemonic"])).unwrap();
        let sealed = format::seal(&mnemonic, s(&fixture["password"]).as_bytes(), &params).unwrap();
        assert_eq!(sealed, contents, "{}", s(&fixture["id"]));
    }
}

#[test]
fn opens_legacy_10k_vaults() {
    let file = load();
    let legacy = file["legacyFixtures"].as_array().unwrap();
    assert!(!legacy.is_empty());
    for fixture in legacy {
        let opened = format::open(
            s(&fixture["fileContents"]),
            s(&fixture["password"]).as_bytes(),
        )
        .unwrap();
        assert_eq!(opened.mnemonic.phrase(), s(&fixture["mnemonic"]));
        assert_eq!(opened.iterations, 10_000);
        assert_eq!(
            format::open(s(&fixture["fileContents"]), b"wrong password").unwrap_err(),
            Error::IncorrectPassword
        );
    }
}

#[test]
fn password_minimum_matches_js() {
    let file = load();
    for case in file["passwordValidation"].as_array().unwrap() {
        assert_eq!(
            s(&case["outcome"]["message"]),
            "Password must be at least 8 characters"
        );
        assert!(!format::is_strong_enough(s(&case["password"])));
    }
    for fixture in file["fixtures"].as_array().unwrap() {
        assert!(
            format::is_strong_enough(s(&fixture["password"])),
            "{}",
            s(&fixture["id"])
        );
    }
}
