//! fc-vault's file reader: the envelope, the passworder payload, and the
//! decrypted plaintext with its mnemonic.
//!
//! The first byte picks what the rest is:
//! - **even: a whole vault file.** `open` derives a key before it decrypts,
//!   so it runs only when the payload asks for at most 64 PBKDF2 rounds
//!   (a missing `keyMetadata` means 10,000). The parsing before the key
//!   always runs, through `read_envelope`. Without the password nothing
//!   decrypts, so this mode stops at the authentication tag.
//! - **odd: the decrypted plaintext.** The target seals it as the vault
//!   does, under a known password with one round, so `open` reaches the
//!   plaintext's JSON, the mnemonic's unescaping and the phrase check. A
//!   plaintext that opens must survive `seal` and `open` again unchanged.

#![no_main]

use std::num::NonZeroU32;

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fc_vault::format::{self, SealParams};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use sha2::Sha256;

type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

/// The most PBKDF2 rounds a vault-file input may ask for: more would only
/// slow the target down without reaching more of the parser.
const MAX_ROUNDS: f64 = 64.0;
const PASSWORD: &[u8] = b"fuzzing password";
const SALT: [u8; 32] = [0x5a; 32];
const IV: [u8; 16] = [0xa5; 16];

fuzz_target!(|data: &[u8]| {
    let Some((&mode, input)) = data.split_first() else {
        return;
    };
    if mode.is_multiple_of(2) {
        vault_file(input);
    } else {
        plaintext(input);
    }
});

fn vault_file(input: &[u8]) {
    let Ok(file) = std::str::from_utf8(input) else {
        return;
    };
    let Ok(payload) = format::read_envelope(file) else {
        return;
    };
    if rounds(&payload).is_some_and(|rounds| rounds <= MAX_ROUNDS) {
        let _ = format::open(file, PASSWORD);
        let _ = format::verify_password(file, PASSWORD);
    }
}

/// The iteration count the payload asks for, read as fc-vault reads it:
/// `keyMetadata.params.iterations`, a number or a numeric string.
fn rounds(payload: &str) -> Option<f64> {
    let payload: Value = serde_json::from_str(payload).ok()?;
    match payload
        .get("keyMetadata")?
        .get("params")?
        .get("iterations")?
    {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn plaintext(input: &[u8]) {
    let rounds = NonZeroU32::MIN;
    let derived = fc_keys::kdf::pbkdf2::<Sha256, 32>(PASSWORD, &SALT, rounds);
    let mut key = aes_gcm::Key::<Aes256Gcm16>::default();
    key.copy_from_slice(derived.as_slice());
    let mut sealed = input.to_vec();
    Aes256Gcm16::new(&key)
        .encrypt_in_place(&Nonce::from(IV), b"", &mut sealed)
        .expect("AES-GCM seals any plaintext");
    let payload = serde_json::json!({
        "data": STANDARD.encode(&sealed),
        "iv": STANDARD.encode(IV),
        "keyMetadata": { "algorithm": "PBKDF2", "params": { "iterations": rounds.get() } },
        "salt": STANDARD.encode(SALT),
    });
    let file = serde_json::json!({
        "version": 1,
        "encrypted": payload.to_string(),
        "createdAt": "2026-10-19T00:00:00.000Z",
    })
    .to_string();

    let Ok(opened) = format::open(&file, PASSWORD) else {
        return;
    };
    let params = SealParams {
        salt: SALT,
        iv: IV,
        iterations: rounds.get(),
        created_at: "2026-10-19T00:00:00.000Z".into(),
    };
    let resealed =
        format::seal(&opened.mnemonic, PASSWORD, &params).expect("an opened phrase seals");
    let reopened = format::open(&resealed, PASSWORD).expect("a sealed vault opens");
    assert_eq!(reopened.mnemonic.phrase(), opened.mnemonic.phrase());
    assert_eq!(reopened.iterations, rounds.get());
}
