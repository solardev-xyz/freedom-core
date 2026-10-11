//! BIP-39 mnemonics with the exact acceptance rules of `@scure/bip39` 2.x,
//! which freedom-browser uses (`validateMnemonic`, `mnemonicToSeedSync`):
//!
//! - the input is normalized to NFKD;
//! - words are separated by single U+0020 spaces only, so leading, trailing
//!   or repeated spaces, tabs and newlines are rejected;
//! - 12, 15, 18, 21 or 24 words, each in the English list (case-sensitive);
//! - the checksum must match;
//! - the seed is PBKDF2-HMAC-SHA512 over the NFKD phrase, salt `"mnemonic"`,
//!   2048 rounds. Freedom never uses a BIP-39 passphrase.

use std::fmt;
use std::sync::OnceLock;

use pbkdf2::pbkdf2_hmac;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::Error;

const ENGLISH: &str = include_str!("wordlist/english.txt");
const VALID_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];
const SEED_ROUNDS: u32 = 2048;

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| ENGLISH.lines().collect())
}

/// Number of words in a generated mnemonic. Freedom creates 12- or 24-word
/// phrases; the others exist for completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    W12,
    W15,
    W18,
    W21,
    W24,
}

impl WordCount {
    fn entropy_len(self) -> usize {
        match self {
            WordCount::W12 => 16,
            WordCount::W15 => 20,
            WordCount::W18 => 24,
            WordCount::W21 => 28,
            WordCount::W24 => 32,
        }
    }
}

/// A validated mnemonic. Keeps the phrase exactly as given, because that is
/// what freedom-browser stores in the vault and shows on export; derivation
/// always uses its NFKD form.
pub struct Mnemonic {
    phrase: Zeroizing<String>,
}

/// A 64-byte BIP-39 seed.
pub struct Seed(Zeroizing<[u8; 64]>);

impl Mnemonic {
    /// Parses `input` with the rules of `@scure/bip39`'s `validateMnemonic`.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let normalized: Zeroizing<String> = Zeroizing::new(input.nfkd().collect());
        decode_entropy(&normalized)?;
        Ok(Mnemonic {
            phrase: Zeroizing::new(input.to_owned()),
        })
    }

    /// Builds the mnemonic for `entropy` (16, 20, 24, 28 or 32 bytes).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Error> {
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(Error::InvalidEntropyLength(entropy.len()));
        }
        Ok(Mnemonic {
            phrase: encode_entropy(entropy),
        })
    }

    /// Generates a new mnemonic from `rng`, like `createMnemonic(strength)`.
    pub fn generate(rng: &mut impl CryptoRngCore, words: WordCount) -> Self {
        let mut entropy = Zeroizing::new([0u8; 32]);
        let entropy = &mut entropy[..words.entropy_len()];
        rng.fill_bytes(entropy);
        Mnemonic {
            phrase: encode_entropy(entropy),
        }
    }

    /// The phrase exactly as given (or as generated). Only for storing in
    /// the vault and for the user-requested export.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The BIP-39 seed (empty passphrase).
    pub fn to_seed(&self) -> Seed {
        self.to_seed_with_passphrase("")
    }

    fn to_seed_with_passphrase(&self, passphrase: &str) -> Seed {
        let normalized: Zeroizing<String> = Zeroizing::new(self.phrase.nfkd().collect());
        let salt: Zeroizing<String> =
            Zeroizing::new(format!("mnemonic{passphrase}").nfkd().collect());
        let mut seed = Zeroizing::new([0u8; 64]);
        pbkdf2_hmac::<Sha512>(
            normalized.as_bytes(),
            salt.as_bytes(),
            SEED_ROUNDS,
            seed.as_mut(),
        );
        Seed(seed)
    }
}

/// Same result as `@scure/bip39`'s `validateMnemonic(input, english)`.
pub fn is_valid_mnemonic(input: &str) -> bool {
    Mnemonic::parse(input).is_ok()
}

/// Encodes entropy whose length is a multiple of 4 bytes as words.
fn encode_entropy(entropy: &[u8]) -> Zeroizing<String> {
    let checksum = Sha256::digest(entropy);
    let entropy_bits = entropy.len() * 8;
    let total_bits = entropy_bits + entropy_bits / 32;
    let bit = |i: usize| -> u16 {
        let byte = if i < entropy_bits {
            entropy[i / 8]
        } else {
            checksum[(i - entropy_bits) / 8]
        };
        u16::from((byte >> (7 - (i % 8))) & 1)
    };
    let words = wordlist();
    let mut phrase = Zeroizing::new(String::with_capacity(total_bits));
    for word_index in 0..total_bits / 11 {
        let mut index: u16 = 0;
        for offset in 0..11 {
            index = (index << 1) | bit(word_index * 11 + offset);
        }
        if word_index > 0 {
            phrase.push(' ');
        }
        phrase.push_str(words[usize::from(index)]);
    }
    phrase
}

/// Decodes an NFKD-normalized phrase to entropy, checking the checksum.
fn decode_entropy(normalized: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let words: Vec<&str> = normalized.split(' ').collect();
    if !VALID_WORD_COUNTS.contains(&words.len()) {
        return Err(Error::InvalidMnemonic);
    }
    let list = wordlist();
    let mut bits: Zeroizing<Vec<bool>> = Zeroizing::new(Vec::with_capacity(words.len() * 11));
    for word in &words {
        let index = list
            .binary_search(word)
            .map_err(|_| Error::InvalidMnemonic)?;
        for offset in (0..11).rev() {
            bits.push((index >> offset) & 1 == 1);
        }
    }
    let checksum_bits = bits.len() / 33;
    let entropy_bits = bits.len() - checksum_bits;
    let mut entropy = Zeroizing::new(vec![0u8; entropy_bits / 8]);
    for (i, bit) in bits[..entropy_bits].iter().enumerate() {
        if *bit {
            entropy[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    let checksum = Sha256::digest(entropy.as_slice());
    for i in 0..checksum_bits {
        let expected = (checksum[i / 8] >> (7 - (i % 8))) & 1 == 1;
        if bits[entropy_bits + i] != expected {
            return Err(Error::InvalidMnemonic);
        }
    }
    Ok(entropy)
}

impl Seed {
    /// The raw 64 seed bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Mnemonic(<redacted>)")
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn wordlist_is_bip39_english() {
        // SHA-256 of bitcoin/bips bip-0039/english.txt.
        assert_eq!(
            hex::encode(Sha256::digest(ENGLISH.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert_eq!(wordlist().len(), 2048);
        assert!(
            wordlist().windows(2).all(|w| w[0] < w[1]),
            "sorted for binary search"
        );
    }

    #[test]
    fn known_seed() {
        let seed = Mnemonic::parse(ABANDON_12).unwrap().to_seed();
        assert_eq!(
            hex::encode(seed.as_bytes()),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn bip39_trezor_vector_with_passphrase() {
        let m = Mnemonic::parse(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        assert_eq!(
            hex::encode(m.to_seed_with_passphrase("TREZOR").as_bytes()),
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        );
    }

    #[test]
    fn entropy_round_trip() {
        for len in [16, 20, 24, 28, 32] {
            let entropy: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(
                decode_entropy(m.phrase()).unwrap().as_slice(),
                entropy.as_slice()
            );
            assert!(is_valid_mnemonic(m.phrase()));
        }
        assert_eq!(
            Mnemonic::from_entropy(&[0; 17]).unwrap_err(),
            Error::InvalidEntropyLength(17)
        );
    }

    #[test]
    fn generate_uses_requested_length() {
        let mut rng = rand_core::OsRng;
        assert_eq!(
            Mnemonic::generate(&mut rng, WordCount::W12)
                .phrase()
                .split(' ')
                .count(),
            12
        );
        assert_eq!(
            Mnemonic::generate(&mut rng, WordCount::W24)
                .phrase()
                .split(' ')
                .count(),
            24
        );
    }

    #[test]
    fn strict_spacing_and_case() {
        assert!(is_valid_mnemonic(ABANDON_12));
        assert!(!is_valid_mnemonic(&format!(" {ABANDON_12}")));
        assert!(!is_valid_mnemonic(&format!("{ABANDON_12} ")));
        assert!(!is_valid_mnemonic(&ABANDON_12.replacen(' ', "  ", 1)));
        assert!(!is_valid_mnemonic(&ABANDON_12.replacen(' ', "\t", 1)));
        assert!(!is_valid_mnemonic(&ABANDON_12.to_uppercase()));
        assert!(!is_valid_mnemonic(&ABANDON_12.replace("about", "abandon")));
        assert!(!is_valid_mnemonic(""));
    }

    #[test]
    fn nfkd_compatibility_forms_are_accepted() {
        // Fullwidth letters decompose to ASCII under NFKD, as in the JS.
        let fullwidth = ABANDON_12.replacen("about", "ａｂｏｕｔ", 1);
        let m = Mnemonic::parse(&fullwidth).unwrap();
        assert_eq!(m.phrase(), fullwidth, "the phrase is kept as given");
        assert_eq!(
            m.to_seed().as_bytes(),
            Mnemonic::parse(ABANDON_12).unwrap().to_seed().as_bytes()
        );
    }

    #[test]
    fn debug_is_redacted() {
        let m = Mnemonic::parse(ABANDON_12).unwrap();
        assert_eq!(format!("{m:?}"), "Mnemonic(<redacted>)");
        assert_eq!(format!("{:?}", m.to_seed()), "Seed(<redacted>)");
    }
}
