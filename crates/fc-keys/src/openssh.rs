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
use zeroize::{Zeroize, Zeroizing};

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
/// the public section of `openssh-key-v1` (design 0008, "The switch": the
/// old identity's node ID, never its secret). `None` for anything else.
/// This is [`PublicKeyReader`] over the whole text, which stops reading
/// where the public key ends.
pub fn public_key_of_private_file(file: &str) -> Option<[u8; 32]> {
    let mut reader = PublicKeyReader::new();
    match reader.feed(file.as_bytes()) {
        Some(found) => found,
        None => reader.finish(),
    }
}

/// The envelope before the public key, at most: the magic, three strings
/// and the key count. Anything longer names no key here.
const MAX_ENVELOPE: usize = 512;
const BEGIN: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";

/// Reads an OpenSSH private key file's public key as its text streams in,
/// decoding only the envelope and its one public-key blob, four base64
/// characters at a time into a fixed, wiped buffer, then stopping: the
/// private section is never decoded, and the bytes after the public key are
/// never looked at (design 0008, "The switch"). Any cipher is read: the
/// public section is never encrypted.
pub struct PublicKeyReader {
    phase: Phase,
    /// The first line, up to the BEGIN marker's length plus a little.
    line: [u8; 48],
    line_len: usize,
    /// The base64 characters of the group being read.
    group: [u8; 4],
    group_len: usize,
    /// What has been decoded: the envelope, then the public key's blob.
    decoded: Zeroizing<[u8; MAX_ENVELOPE]>,
    decoded_len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Begin,
    Body,
    Done,
}

impl Default for PublicKeyReader {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PublicKeyReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyReader").finish_non_exhaustive()
    }
}

impl PublicKeyReader {
    pub fn new() -> Self {
        Self {
            phase: Phase::Begin,
            line: [0; 48],
            line_len: 0,
            group: [0; 4],
            group_len: 0,
            decoded: Zeroizing::new([0; MAX_ENVELOPE]),
            decoded_len: 0,
        }
    }

    /// Feeds the next bytes of the file. `Some(Some(key))` once the public
    /// key is read, `Some(None)` once the file can't name one; `None` while
    /// it needs more. After `Some`, nothing more is read.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<Option<[u8; 32]>> {
        for &byte in bytes {
            let step = match self.phase {
                Phase::Done => return Some(None),
                Phase::Begin => self.begin(byte),
                Phase::Body => self.body(byte),
            };
            if let Some(found) = step {
                self.phase = Phase::Done;
                self.group.zeroize();
                return Some(found);
            }
        }
        None
    }

    /// The end of the file: there was no public key.
    pub fn finish(self) -> Option<[u8; 32]> {
        None
    }

    fn begin(&mut self, byte: u8) -> Option<Option<[u8; 32]>> {
        match byte {
            b'\n' => {
                let line = trim(&self.line[..self.line_len]);
                if line == BEGIN {
                    self.phase = Phase::Body;
                    None
                } else {
                    Some(None)
                }
            }
            _ if self.line_len < self.line.len() => {
                self.line[self.line_len] = byte;
                self.line_len += 1;
                None
            }
            _ => Some(None),
        }
    }

    fn body(&mut self, byte: u8) -> Option<Option<[u8; 32]>> {
        if byte.is_ascii_whitespace() {
            return None;
        }
        // The END marker, or anything that isn't base64, before the key.
        if !(byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/') {
            return Some(None);
        }
        self.group[self.group_len] = byte;
        self.group_len += 1;
        if self.group_len < 4 {
            return None;
        }
        self.group_len = 0;
        let mut three = [0u8; 3];
        let written = STANDARD.decode_slice(self.group, &mut three);
        self.group.zeroize();
        let fits = matches!(written, Ok(3)) && self.decoded_len + 3 <= MAX_ENVELOPE;
        if !fits {
            three.zeroize();
            return Some(None);
        }
        self.decoded[self.decoded_len..self.decoded_len + 3].copy_from_slice(&three);
        three.zeroize();
        self.decoded_len += 3;
        self.parse()
    }

    /// The public key, once everything before it and its blob are decoded;
    /// `Some(None)` if the envelope can't hold one.
    fn parse(&self) -> Option<Option<[u8; 32]>> {
        let have = &self.decoded[..self.decoded_len];
        let magic = b"openssh-key-v1\0";
        if have.len() < magic.len() {
            return None;
        }
        if &have[..magic.len()] != magic {
            return Some(None);
        }
        let mut rest = &have[magic.len()..];
        for _ in 0..3 {
            // The cipher, the KDF and its options.
            match need_string(&mut rest) {
                Need::More => return None,
                Need::Never => return Some(None),
                Need::Got(_) => {}
            }
        }
        // Not all of it yet: `None`, needing more.
        let count = take_u32(&mut rest)?;
        if count != 1 {
            return Some(None);
        }
        match need_string(&mut rest) {
            Need::More => None,
            Need::Never => Some(None),
            Need::Got(blob) => Some(public_of_blob(blob)),
        }
    }
}

/// A length-prefixed string, if all of it is there yet.
enum Need<'a> {
    More,
    /// Longer than the envelope can hold.
    Never,
    Got(&'a [u8]),
}

fn need_string<'a>(rest: &mut &'a [u8]) -> Need<'a> {
    let Some((head, tail)) = rest.split_first_chunk::<4>() else {
        return Need::More;
    };
    let Ok(len) = usize::try_from(u32::from_be_bytes(*head)) else {
        return Need::Never;
    };
    if len > MAX_ENVELOPE {
        return Need::Never;
    }
    if len > tail.len() {
        return Need::More;
    }
    let (string, after) = tail.split_at(len);
    *rest = after;
    Need::Got(string)
}

fn trim(line: &[u8]) -> &[u8] {
    let start = line
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(line.len());
    let end = line
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &line[start..end]
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

    /// Review of #177: the switch reads the public part only. Whatever
    /// follows the public key in a private key file, its private section
    /// corrupted, cut off, or another key after it, the key is read the
    /// same, and nothing after it is decoded.
    #[test]
    fn only_the_public_part_of_a_private_file_is_read() {
        let seed = crate::Mnemonic::from_entropy(&[7u8; 16]).unwrap().to_seed();
        let key = crate::freedom::derive_all(&seed).unwrap().radicle;
        let public = key.public_key();
        let file = private_key_file_with_check(&key, "c", 1);
        let lines: Vec<&str> = file.lines().collect();
        // The public key's blob ends within the third line of base64: what
        // comes after it is the private section.
        let head = format!("{}\n{}\n{}\n", lines[0], lines[1], lines[2]);
        let mut corrupt_tail = file.to_string();
        let last_body = lines[lines.len() - 2];
        corrupt_tail = corrupt_tail.replace(last_body, &"!".repeat(last_body.len()));
        for case in [
            corrupt_tail,
            head.clone(),
            format!("{head}not base64 at all\n"),
            format!("{}{}", file.as_str(), file.as_str()),
            file.replace("-----END OPENSSH PRIVATE KEY-----\n", ""),
            file.replace('\n', "\r\n"),
        ] {
            assert_eq!(public_key_of_private_file(&case), Some(public), "{case}");
        }
        // Fed a byte at a time, it stops at the key.
        let mut reader = PublicKeyReader::new();
        let mut fed = 0;
        let mut found = None;
        for byte in file.as_bytes() {
            fed += 1;
            if let Some(result) = reader.feed(&[*byte]) {
                found = result;
                break;
            }
        }
        assert_eq!(found, Some(public));
        assert!(fed < file.len() / 2, "read {fed} of {} bytes", file.len());
        // An encrypted file's public key is read the same: only the
        // envelope's strings differ.
        let mut blob = Vec::new();
        blob.extend_from_slice(b"openssh-key-v1\0");
        put_string(&mut blob, b"aes256-ctr");
        put_string(&mut blob, b"bcrypt");
        put_string(&mut blob, &[0x11; 24]);
        blob.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut blob, &public_blob(&public));
        put_string(&mut blob, &[0xEE; 160]);
        let encrypted = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            STANDARD.encode(&blob)
        );
        assert_eq!(public_key_of_private_file(&encrypted), Some(public));
        // Two keys, or an envelope longer than any key's: none.
        let mut two = blob.clone();
        two[15 + 4 + 10 + 4 + 6 + 4 + 24..][..4].copy_from_slice(&2u32.to_be_bytes());
        let two = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n",
            STANDARD.encode(&two)
        );
        assert_eq!(public_key_of_private_file(&two), None);
        let mut long = Vec::new();
        long.extend_from_slice(b"openssh-key-v1\0");
        put_string(&mut long, &[b'x'; 600]);
        let long = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n",
            STANDARD.encode(&long)
        );
        assert_eq!(public_key_of_private_file(&long), None);
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
