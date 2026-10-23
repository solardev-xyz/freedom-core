//! fc-keys' OpenSSH readers (design 0008, "The switch"): the streaming
//! [`PublicKeyReader`] over a private key file, which decodes only up to
//! the public key, and `public_key_of_line` over a public key line.
//!
//! The first byte picks how the rest is used:
//! - `% 64 + 1`: the size of the pieces the reader is fed, so the file is
//!   cut everywhere a read could cut it;
//! - **top bit clear:** the rest is a file, or a line;
//! - **top bit set:** the rest picks a key, a check integer and a comment,
//!   and the writers' file and line for them are read back.
//!
//! It checks, besides panics:
//! - fed in pieces, the reader finds what it finds fed the whole file at
//!   once (`public_key_of_private_file`), and once it has answered it
//!   reads nothing more;
//! - a key a line names is named again by the line written for it;
//! - the file and the line the writers make, for any comment and check
//!   integer, read back to their key, in any pieces.

#![no_main]

use std::sync::OnceLock;

use fc_keys::openssh::{
    PublicKeyReader, private_key_file_with_check, public_key_line, public_key_of_line,
    public_key_of_private_file,
};
use fc_keys::{DerivationPath, Ed25519Key, Mnemonic, derive_ed25519};
use libfuzzer_sys::fuzz_target;

/// A few keys, derived once: deriving per input would cost a PBKDF2 run.
fn keys() -> &'static [Ed25519Key] {
    static KEYS: OnceLock<Vec<Ed25519Key>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let seed = Mnemonic::from_entropy(&[7; 16]).unwrap().to_seed();
        (0..4)
            .map(|i| {
                let path: DerivationPath = format!("m/44'/1'/{i}'").parse().unwrap();
                derive_ed25519(&seed, &path).unwrap()
            })
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let piece = usize::from(mode % 64) + 1;
    if mode & 0x80 != 0 {
        written(rest, piece);
        return;
    }
    let found = streamed(rest, piece);
    if let Ok(text) = std::str::from_utf8(rest) {
        assert_eq!(public_key_of_private_file(text), found);
        if let Some(key) = public_key_of_line(text) {
            assert_eq!(
                public_key_of_line(&public_key_line(&key, "fuzz")),
                Some(key)
            );
        }
    }
});

/// The reader over `bytes`, fed `piece` bytes at a time.
fn streamed(bytes: &[u8], piece: usize) -> Option<[u8; 32]> {
    let mut reader = PublicKeyReader::new();
    for chunk in bytes.chunks(piece) {
        if let Some(found) = reader.feed(chunk) {
            assert_eq!(reader.feed(b"more"), Some(None));
            return found;
        }
    }
    reader.finish()
}

fn written(rest: &[u8], piece: usize) {
    let Some((&which, rest)) = rest.split_first() else {
        return;
    };
    let Some((check, comment)) = rest.split_first_chunk::<4>() else {
        return;
    };
    let key = &keys()[usize::from(which) % keys().len()];
    let comment = String::from_utf8_lossy(comment);
    let file = private_key_file_with_check(key, &comment, u32::from_be_bytes(*check));
    assert_eq!(public_key_of_private_file(&file), Some(key.public_key()));
    assert_eq!(streamed(file.as_bytes(), piece), Some(key.public_key()));
    let line = public_key_line(&key.public_key(), &comment);
    // A comment with a line break makes two lines, which name no key.
    if !comment.contains(['\n', '\r']) {
        assert_eq!(public_key_of_line(&line), Some(key.public_key()));
    }
}
