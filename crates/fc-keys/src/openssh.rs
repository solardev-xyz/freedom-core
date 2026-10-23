//! OpenSSH v1 Ed25519 key files for the Radicle node, byte-identical to
//! freedom-browser's `createRadicleIdentity` (`formats.js`):
//!
//! - unencrypted (`cipher none`, `kdf none`), one key;
//! - the 4-byte check integer appears twice, and is random in production;
//! - padding bytes `01 02 …` up to the next multiple of 8, so 0–7 bytes,
//!   as OpenSSH writes them. The reference pads an aligned section with a
//!   full 8 bytes; OpenSSH reads that, but ssh-key (Radicle's reader)
//!   refuses it (deviation `openssh-padding`, #77);
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
    // None for an aligned section: ssh-key refuses a full block of it.
    let padding = (8 - private_section.len() % 8) % 8;
    for i in 1..=padding {
        // `padding` is 0..=7, so this never truncates.
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

/// The Ed25519 public key an OpenSSH private key file names in the clear:
/// the public section of `openssh-key-v1`, read without decoding the
/// private section into a key (design 0008, "The switch": the old
/// identity's node ID, never its secret). The public section is never
/// encrypted, so any cipher is read. `None` for anything else: not one PEM
/// block of that type, more than one key, or a key that isn't Ed25519.
pub fn public_key_of_private_file(file: &str) -> Option<[u8; 32]> {
    let mut lines = file.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.next()? != "-----BEGIN OPENSSH PRIVATE KEY-----" {
        return None;
    }
    let mut body = Zeroizing::new(String::new());
    let mut ended = false;
    for line in lines.by_ref() {
        if line == "-----END OPENSSH PRIVATE KEY-----" {
            ended = true;
            break;
        }
        body.push_str(line);
    }
    if !ended || lines.next().is_some() {
        return None;
    }
    // The blob holds the private section too: decoded into a wiped buffer.
    let blob = Zeroizing::new(STANDARD.decode(body.as_bytes()).ok()?);
    let mut rest: &[u8] = blob.strip_prefix(b"openssh-key-v1\0")?;
    take_string(&mut rest)?; // cipher
    take_string(&mut rest)?; // kdf
    take_string(&mut rest)?; // kdf options
    if take_u32(&mut rest)? != 1 {
        return None;
    }
    public_of_blob(take_string(&mut rest)?)
}

/// The Ed25519 public key a public key line names: `ssh-ed25519 <base64>`,
/// then an optional comment. `None` for anything else.
pub fn public_key_of_line(text: &str) -> Option<[u8; 32]> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let mut fields = line.split_ascii_whitespace();
    if fields.next()?.as_bytes() != KEY_TYPE {
        return None;
    }
    let blob = STANDARD.decode(fields.next()?).ok()?;
    public_of_blob(&blob)
}

/// An `ssh-ed25519` public key blob: the type, then 32 bytes, nothing more.
fn public_of_blob(blob: &[u8]) -> Option<[u8; 32]> {
    let mut rest = blob;
    if take_string(&mut rest)? != KEY_TYPE {
        return None;
    }
    let key = take_string(&mut rest)?.try_into().ok()?;
    rest.is_empty().then_some(key)
}

fn take_u32(rest: &mut &[u8]) -> Option<u32> {
    let (head, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    Some(u32::from_be_bytes(*head))
}

fn take_string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::try_from(take_u32(rest)?).ok()?;
    if len > rest.len() {
        return None;
    }
    let (string, tail) = rest.split_at(len);
    *rest = tail;
    Some(string)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The private section of a file, read as OpenSSH reads it.
    fn private_section(file: &str) -> Vec<u8> {
        let body: String = file
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let blob = STANDARD.decode(body).unwrap();
        let mut at = b"openssh-key-v1\0".len();
        let string = |at: &mut usize| {
            let len = u32::from_be_bytes(blob[*at..*at + 4].try_into().unwrap()) as usize;
            *at += 4 + len;
            blob[*at - len..*at].to_vec()
        };
        string(&mut at); // cipher
        string(&mut at); // kdf
        string(&mut at); // kdf options
        at += 4; // one key
        string(&mut at); // public key
        let section = string(&mut at);
        assert_eq!(at, blob.len());
        section
    }

    #[test]
    fn the_public_key_is_read_back_from_both_files() {
        let seed = crate::Mnemonic::from_entropy(&[7u8; 16]).unwrap().to_seed();
        let key = crate::freedom::derive_all(&seed).unwrap().radicle;
        let public = key.public_key();
        for check in [0, 1, 0xdead_beef] {
            for comment in ["", "FreedomBrowser", "a comment with spaces"] {
                let file = private_key_file_with_check(&key, comment, check);
                assert_eq!(public_key_of_private_file(&file), Some(public));
                assert_eq!(
                    public_key_of_line(&public_key_line(&public, comment)),
                    Some(public)
                );
            }
        }
    }

    #[test]
    fn anything_else_names_no_key() {
        let seed = crate::Mnemonic::from_entropy(&[7u8; 16]).unwrap().to_seed();
        let key = crate::freedom::derive_all(&seed).unwrap().radicle;
        let public = key.public_key();
        let file = private_key_file_with_check(&key, "c", 1);
        let line = public_key_line(&public, "c");
        let mut cases: Vec<String> = vec![
            String::new(),
            "garbage".into(),
            file.replace("OPENSSH PRIVATE KEY", "RSA PRIVATE KEY"),
            file.replace("-----END OPENSSH PRIVATE KEY-----\n", ""),
            format!("{}{}", file.as_str(), file.as_str()),
            line.replace("ssh-ed25519 ", "ssh-rsa "),
            format!("{line}{line}"),
            "ssh-ed25519 !!!".into(),
        ];
        // Truncated bodies.
        let body: String = file.lines().filter(|l| !l.starts_with("-----")).collect();
        for cut in [10, 30, 60] {
            cases.push(format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                &body[..cut]
            ));
        }
        // A blob of another type, and a key of the wrong length.
        let mut wrong = Vec::new();
        put_string(&mut wrong, b"ssh-ed25519");
        put_string(&mut wrong, &[1u8; 31]);
        cases.push(format!("ssh-ed25519 {}", STANDARD.encode(&wrong)));
        let mut trailing = public_blob(&public);
        trailing.push(0);
        cases.push(format!("ssh-ed25519 {}", STANDARD.encode(&trailing)));
        for case in &cases {
            assert_eq!(public_key_of_private_file(case), None, "{case}");
            assert_eq!(public_key_of_line(case), None, "{case}");
        }
    }

    #[test]
    fn padding_never_fills_a_whole_block() {
        // #77: a section already aligned (131 bytes plus a 5-byte alias)
        // gets no padding; ssh-key refuses 8 bytes of it.
        let seed = crate::Mnemonic::from_entropy(&[3u8; 16]).unwrap().to_seed();
        let key = crate::freedom::derive_all(&seed).unwrap().radicle;
        for len in 0..=24 {
            let comment = "a".repeat(len);
            let section = private_section(&private_key_file_with_check(&key, &comment, 7));
            assert_eq!(section.len() % 8, 0, "{len}");
            let unpadded = 131 + len;
            let padding = &section[unpadded..];
            assert!(padding.len() < 8, "{len}");
            assert!(
                padding.iter().zip(1u8..).all(|(byte, i)| *byte == i),
                "{len}"
            );
        }
    }
}
