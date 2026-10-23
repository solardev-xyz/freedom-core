//! `nodes.seal_radicle_key` through the real binary (design 0008, "The
//! sealed release"): the Radicle node key, sealed to the key a service made
//! for one start, and nothing else.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// A service's key for one start, from fixed keying material.
fn recipient(seed: u8) -> fc_seal::RecipientKey {
    struct Fixed(u8);
    impl rand_core::TryRng for Fixed {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from(self.0))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.0))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(self.0);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Fixed {}
    fc_seal::RecipientKey::generate(&mut Fixed(seed)).unwrap()
}

fn seal_request(recipient: &str) -> Value {
    json!({ "recipient": recipient })
}

/// A core with the abandon...about wallet imported (unlocked). The next
/// free request ID is 3.
fn imported() -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let imported = core.call(
        2,
        "vault.import",
        json!({
            "password_b64": b64(b"testpass1"),
            "mnemonic_b64": b64(ABANDON.as_bytes()),
        }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    (root, core)
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// The sealed key opens with the recipient's private half to the key whose
/// public half `keys.addresses` names as the Radicle key: the 32-byte seed
/// at `m/44'/73404'/0'/0'/0'`, and only that.
#[test]
fn it_seals_the_radicle_node_key_to_the_recipient() {
    let (_root, mut core) = imported();
    let service = recipient(1);
    let sealed = core.call_shell(
        3,
        "nodes.seal_radicle_key",
        seal_request(&b64(&service.public_key())),
    );
    let result = &sealed["result"];
    let mut fields: Vec<&str> = result
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["ciphertext", "enc"], "{sealed}");
    let enc = STANDARD.decode(result["enc"].as_str().unwrap()).unwrap();
    let ciphertext = STANDARD
        .decode(result["ciphertext"].as_str().unwrap())
        .unwrap();
    assert_eq!(enc.len(), 32);
    assert_eq!(ciphertext.len(), 48);
    let key = service.open(&enc, &ciphertext).unwrap();

    let addresses = core.call(4, "keys.addresses", json!({}));
    let public = unhex(
        addresses["result"]["radicle"]["public_key"]
            .as_str()
            .unwrap(),
    );
    let derived = ed25519_dalek::SigningKey::from_bytes(&key)
        .verifying_key()
        .to_bytes();
    assert_eq!(derived.to_vec(), public);

    // Each seal is fresh: a second one to the same recipient differs, and
    // only a new start's key opens what is sealed to it.
    let again = core.call_shell(
        5,
        "nodes.seal_radicle_key",
        seal_request(&b64(&recipient(1).public_key())),
    );
    assert_ne!(again["result"]["enc"], sealed["result"]["enc"]);
    let other = recipient(2);
    let to_other = core.call_shell(
        6,
        "nodes.seal_radicle_key",
        seal_request(&b64(&other.public_key())),
    );
    assert!(
        recipient(1)
            .open(
                &STANDARD
                    .decode(to_other["result"]["enc"].as_str().unwrap())
                    .unwrap(),
                &STANDARD
                    .decode(to_other["result"]["ciphertext"].as_str().unwrap())
                    .unwrap(),
            )
            .is_err()
    );
}

#[test]
fn only_main_may_call_it() {
    let (_root, mut core) = imported();
    let refused = core.call(
        3,
        "nodes.seal_radicle_key",
        seal_request(&b64(&recipient(1).public_key())),
    );
    assert_eq!(refused["error"]["code"], "forbidden", "{refused}");
    assert!(refused.get("result").is_none());
}

#[test]
fn hello_names_it() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello();
    let names: Vec<&str> = hello["result"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(names.contains(&"nodes.seal_radicle_key"), "{hello}");
}

/// No vault: `no_vault`, the one answer that leads main to a throwaway key.
#[test]
fn without_a_vault_it_answers_no_vault() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let reply = core.call_shell(
        2,
        "nodes.seal_radicle_key",
        seal_request(&b64(&recipient(1).public_key())),
    );
    assert_eq!(reply["error"]["code"], "no_vault", "{reply}");
}

/// Locked: `vault_locked`, never `no_vault`, and nothing sealed. A lock
/// sent before the request locks first; one sent after it locks after the
/// reply has left (the inline method's epoch is the reply's).
#[test]
fn a_locked_vault_answers_vault_locked() {
    let (_root, mut core) = imported();
    let service = recipient(1);
    let mut burst = Vec::new();
    burst.extend(frame(&shell_request(
        3,
        "nodes.seal_radicle_key",
        seal_request(&b64(&service.public_key())),
    )));
    burst.extend(frame(&request(4, "vault.lock", json!({}))));
    burst.extend(frame(&shell_request(
        5,
        "nodes.seal_radicle_key",
        seal_request(&b64(&service.public_key())),
    )));
    core.send_raw(&burst);
    let first = core.until_response(3);
    assert!(first["result"]["ciphertext"].is_string(), "{first}");
    assert_eq!(core.until_response(4)["result"], json!({}));
    let after = core.until_response(5);
    assert_eq!(after["error"]["code"], "vault_locked", "{after}");
    assert!(after.get("result").is_none());
}

/// A recipient that isn't 32 bytes of canonical base64, or that gives the
/// all-zero shared secret, is `invalid_argument`, whatever the vault does.
#[test]
fn a_bad_recipient_is_invalid_argument() {
    let (_root, mut core) = imported();
    let mut low_order = [0u8; 32];
    low_order[0] = 1;
    let bad = [
        json!({ "recipient": b64(&[7u8; 31]) }),
        json!({ "recipient": b64(&[7u8; 33]) }),
        json!({ "recipient": "not base64!" }),
        json!({ "recipient": "" }),
        json!({ "recipient": 32 }),
        json!({}),
        json!({ "recipient": b64(&[0u8; 32]) }),
        json!({ "recipient": b64(&low_order) }),
    ];
    for (i, params) in bad.into_iter().enumerate() {
        let id = 10 + u64::try_from(i).unwrap();
        let reply = core.call_shell(id, "nodes.seal_radicle_key", params.clone());
        assert_eq!(
            reply["error"]["code"], "invalid_argument",
            "{params}: {reply}"
        );
    }
}

/// The log names the method, never the recipient or the sealed key.
#[test]
fn nothing_but_the_method_reaches_the_log() {
    let (_root, mut core) = imported();
    let service = recipient(1);
    let recipient_b64 = b64(&service.public_key());
    let sealed = core.call_shell(3, "nodes.seal_radicle_key", seal_request(&recipient_b64));
    let enc = sealed["result"]["enc"].as_str().unwrap().to_owned();
    let ciphertext = sealed["result"]["ciphertext"].as_str().unwrap().to_owned();
    core.close_stdin();
    core.exit_code(std::time::Duration::from_secs(10));
    let log = core.stderr();
    for secret in [&recipient_b64, &enc, &ciphertext] {
        assert!(!log.contains(secret.as_str()), "the log carries {secret}");
    }
}
