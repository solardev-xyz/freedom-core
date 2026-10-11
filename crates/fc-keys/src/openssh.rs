//! OpenSSH v1 Ed25519 key files for the Radicle node, byte-identical to
//! freedom-browser's `createRadicleIdentity` (`formats.js`):
//!
//! - unencrypted (`cipher none`, `kdf none`), one key;
//! - the 4-byte check integer appears twice, and is random in production;
//! - padding bytes `01 02 …` up to the next multiple of 8, so 1–8 bytes;
//! - standard base64 wrapped at 70 characters, a trailing newline after the
//!   END line;
//! - public line `ssh-ed25519 <base64> <comment>\n`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::{Ed25519Key, Error};

const KEY_TYPE: &[u8] = b"ssh-ed25519";
const LINE_WIDTH: usize = 70;

/// The private key file, with a random check integer.
pub fn private_key_file<R: TryCryptoRng + ?Sized>(
    key: &Ed25519Key,
    comment: &str,
    rng: &mut R,
) -> Result<Zeroizing<String>, Error> {
    let check = rng.try_next_u32().map_err(|_| Error::Randomness)?;
    Ok(private_key_file_with_check(key, comment, check))
}

/// The private key file with a given check integer; reproduces an existing
/// file exactly.
pub fn private_key_file_with_check(
    key: &Ed25519Key,
    comment: &str,
    check: u32,
) -> Zeroizing<String> {
    let public = key.public_key();
    let secret = key.to_secret_bytes();
    let mut keypair = Zeroizing::new([0u8; 64]);
    keypair[..32].copy_from_slice(secret.as_slice());
    keypair[32..].copy_from_slice(&public);

    let mut private_section = Zeroizing::new(Vec::with_capacity(160 + comment.len()));
    private_section.extend_from_slice(&check.to_be_bytes());
    private_section.extend_from_slice(&check.to_be_bytes());
    put_string(&mut private_section, KEY_TYPE);
    put_string(&mut private_section, &public);
    put_string(&mut private_section, keypair.as_slice());
    put_string(&mut private_section, comment.as_bytes());
    let padding = 8 - private_section.len() % 8;
    for i in 1..=padding {
        // `padding` is 1..=8, so this never truncates.
        private_section.push(i as u8);
    }

    let mut blob = Zeroizing::new(Vec::with_capacity(64 + private_section.len()));
    blob.extend_from_slice(b"openssh-key-v1\0");
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"");
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, &public_blob(&public));
    put_string(&mut blob, private_section.as_slice());

    let mut encoded = Zeroizing::new(String::with_capacity(
        base64::encoded_len(blob.len(), true).unwrap_or(0),
    ));
    STANDARD.encode_string(blob.as_slice(), &mut encoded);

    let mut file = Zeroizing::new(String::with_capacity(
        encoded.len() + encoded.len() / LINE_WIDTH + 80,
    ));
    file.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(LINE_WIDTH) {
        // Base64 output is ASCII, so every chunk is valid UTF-8.
        file.push_str(std::str::from_utf8(line).unwrap_or_default());
        file.push('\n');
    }
    file.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    file
}

/// The public key line: `ssh-ed25519 <base64> <comment>\n`.
pub fn public_key_line(public: &[u8; 32], comment: &str) -> String {
    format!(
        "ssh-ed25519 {} {comment}\n",
        STANDARD.encode(public_blob(public))
    )
}

fn public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    put_string(&mut blob, KEY_TYPE);
    put_string(&mut blob, public);
    blob
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    // SSH strings are u32-length-prefixed; our inputs are far below 4 GiB.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}
