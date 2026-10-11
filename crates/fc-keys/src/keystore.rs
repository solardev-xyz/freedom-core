//! Web3 Secret Storage v3 keystores, byte-identical to ethers v6's
//! `Wallet.encrypt` for a plain private key, which is what freedom-browser
//! writes for the Bee/Ant node (`createBeeKeystore`):
//!
//! - the password is NFKC-normalized (ethers' `getPassword`);
//! - scrypt with N = 2^17, r = 8, p = 1, 32-byte output;
//! - AES-128-CTR under the first 16 bytes of the scrypt output;
//! - MAC = Keccak-256(scrypt output [16..32] || ciphertext);
//! - compact JSON in ethers' field order, address lowercase without `0x`,
//!   and a version-4 UUID as `id`.

use std::fmt;

use aes::cipher::{KeyIvInit, StreamCipher};
use k256::ecdsa::SigningKey;
use rand_core::TryCryptoRng;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{Address, Error, Secp256k1Key};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

const SCRYPT_LOG_N: u8 = 17;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const DKLEN: usize = 32;
/// The most expensive scrypt cost `decrypt` accepts (N = 2^18, 256 MiB).
const MAX_LOG_N: u8 = 18;

/// The random inputs of one keystore. Fixed values reproduce a keystore
/// exactly; [`KeystoreParams::random`] is what new keystores use.
#[derive(Clone, PartialEq, Eq)]
pub struct KeystoreParams {
    pub salt: [u8; 32],
    pub iv: [u8; 16],
    /// UUID bytes; the version-4 and variant bits are set when encoding,
    /// as ethers' `uuidV4` does.
    pub uuid: [u8; 16],
}

impl KeystoreParams {
    pub fn random<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, Error> {
        let mut params = KeystoreParams {
            salt: [0; 32],
            iv: [0; 16],
            uuid: [0; 16],
        };
        for buf in [
            &mut params.salt[..],
            &mut params.iv[..],
            &mut params.uuid[..],
        ] {
            rng.try_fill_bytes(buf).map_err(|_| Error::Randomness)?;
        }
        Ok(params)
    }
}

impl fmt::Debug for KeystoreParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeystoreParams(..)")
    }
}

/// Encrypts `key` with `password`. Returns the keystore JSON.
pub fn encrypt(
    key: &Secp256k1Key,
    password: &str,
    params: &KeystoreParams,
) -> Result<String, Error> {
    let derived = derive(password, &params.salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
    let mut ciphertext = key.to_secret_bytes();
    apply_ctr(&derived, &params.iv, ciphertext.as_mut_slice());
    let mac = mac(&derived, ciphertext.as_slice());
    let address = hex(key.address().as_bytes());
    Ok(format!(
        concat!(
            r#"{{"address":"{address}","id":"{id}","version":3,"Crypto":{{"cipher":"aes-128-ctr","#,
            r#""cipherparams":{{"iv":"{iv}"}},"ciphertext":"{ciphertext}","kdf":"scrypt","#,
            r#""kdfparams":{{"salt":"{salt}","n":{n},"dklen":{dklen},"p":{p},"r":{r}}},"mac":"{mac}"}}}}"#
        ),
        address = address,
        id = uuid_v4(params.uuid),
        iv = hex(&params.iv),
        ciphertext = hex(ciphertext.as_slice()),
        salt = hex(&params.salt),
        n = 1u32 << SCRYPT_LOG_N,
        dklen = DKLEN,
        p = SCRYPT_P,
        r = SCRYPT_R,
        mac = hex(&mac),
    ))
}

/// A private key recovered from a keystore.
pub struct DecryptedKey {
    secret: Zeroizing<[u8; 32]>,
    address: Address,
}

impl DecryptedKey {
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.secret.clone()
    }
}

impl fmt::Debug for DecryptedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedKey")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Keystore {
    address: Option<String>,
    version: u32,
    #[serde(rename = "Crypto", alias = "crypto")]
    crypto: Crypto,
}

#[derive(Deserialize)]
struct Crypto {
    cipher: String,
    cipherparams: CipherParams,
    ciphertext: String,
    kdf: String,
    kdfparams: ScryptParams,
    mac: String,
}

#[derive(Deserialize)]
struct CipherParams {
    iv: String,
}

#[derive(Deserialize)]
struct ScryptParams {
    salt: String,
    n: u64,
    r: u32,
    p: u32,
    dklen: usize,
}

/// Decrypts a scrypt / AES-128-CTR v3 keystore, as written by ethers or by
/// [`encrypt`]. The password is NFKC-normalized first.
pub fn decrypt(json: &str, password: &str) -> Result<DecryptedKey, Error> {
    let keystore: Keystore =
        serde_json::from_str(json).map_err(|_| Error::InvalidKeystore("malformed JSON"))?;
    if keystore.version != 3 {
        return Err(Error::InvalidKeystore("version is not 3"));
    }
    let crypto = &keystore.crypto;
    if crypto.cipher != "aes-128-ctr" {
        return Err(Error::InvalidKeystore("cipher is not aes-128-ctr"));
    }
    if crypto.kdf != "scrypt" {
        return Err(Error::InvalidKeystore("kdf is not scrypt"));
    }
    let kdf = &crypto.kdfparams;
    if kdf.dklen != DKLEN {
        return Err(Error::InvalidKeystore("dklen is not 32"));
    }
    if !kdf.n.is_power_of_two() || kdf.n < 2 {
        return Err(Error::InvalidKeystore("n is not a power of two"));
    }
    let log_n = u8::try_from(kdf.n.trailing_zeros())
        .ok()
        .filter(|log_n| *log_n <= MAX_LOG_N)
        .ok_or(Error::InvalidKeystore("n is too large"))?;
    if kdf.r != SCRYPT_R || kdf.p != SCRYPT_P {
        return Err(Error::InvalidKeystore("unsupported r or p"));
    }
    let salt = unhex(&kdf.salt)?;
    let iv: [u8; 16] = unhex(&crypto.cipherparams.iv)?
        .try_into()
        .map_err(|_| Error::InvalidKeystore("iv is not 16 bytes"))?;
    let ciphertext = unhex(&crypto.ciphertext)?;
    if ciphertext.len() != 32 {
        return Err(Error::InvalidKeystore("ciphertext is not 32 bytes"));
    }
    let expected_mac = unhex(&crypto.mac)?;

    let derived = derive(password, &salt, log_n, kdf.r, kdf.p)?;
    if !constant_time_eq(&mac(&derived, &ciphertext), &expected_mac) {
        return Err(Error::IncorrectPassword);
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&ciphertext);
    apply_ctr(&derived, &iv, secret.as_mut_slice());

    let signing_key = SigningKey::from_slice(secret.as_slice())
        .map_err(|_| Error::InvalidKeystore("invalid private key"))?;
    let address = crate::secp256k1::address_of(&signing_key);
    if let Some(stored) = &keystore.address {
        let stored = stored.strip_prefix("0x").unwrap_or(stored);
        if !stored.eq_ignore_ascii_case(&hex(address.as_bytes())) {
            return Err(Error::InvalidKeystore("address does not match the key"));
        }
    }
    Ok(DecryptedKey { secret, address })
}

fn derive(
    password: &str,
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
) -> Result<Zeroizing<[u8; DKLEN]>, Error> {
    let password: Zeroizing<String> = Zeroizing::new(password.nfkc().collect());
    let params = scrypt::Params::new(log_n, r, p)
        .map_err(|_| Error::InvalidKeystore("invalid scrypt parameters"))?;
    let mut derived = Zeroizing::new([0u8; DKLEN]);
    scrypt::scrypt(password.as_bytes(), salt, &params, derived.as_mut_slice())
        .map_err(|_| Error::InvalidKeystore("invalid scrypt parameters"))?;
    Ok(derived)
}

fn apply_ctr(derived: &[u8; DKLEN], iv: &[u8; 16], data: &mut [u8]) {
    let mut key = Zeroizing::new(aes::cipher::Key::<Aes128Ctr>::default());
    key.copy_from_slice(&derived[..16]);
    let mut cipher = Aes128Ctr::new(&key, &(*iv).into());
    cipher.apply_keystream(data);
}

fn mac(derived: &[u8; DKLEN], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(&derived[16..32]);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn unhex(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error::InvalidKeystore("odd-length hex"));
    }
    let digit = |c: u8| -> Result<u8, Error> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(Error::InvalidKeystore("invalid hex")),
        }
    };
    pairs
        .iter()
        .map(|[high, low]| Ok((digit(*high)? << 4) | digit(*low)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_bits() {
        assert_eq!(uuid_v4([0xff; 16]), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert_eq!(uuid_v4([0x00; 16]), "00000000-0000-4000-8000-000000000000");
    }

    #[test]
    fn rejects_bad_parameters() {
        let base = r#"{"address":"00","version":3,"Crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"00000000000000000000000000000000"},"ciphertext":"0000000000000000000000000000000000000000000000000000000000000000","kdf":"scrypt","kdfparams":{"salt":"00","n":N,"dklen":32,"p":1,"r":8},"mac":"00"}}"#;
        assert_eq!(
            decrypt(&base.replace('N', "1048576"), "x").unwrap_err(),
            Error::InvalidKeystore("n is too large")
        );
        assert_eq!(
            decrypt(&base.replace('N', "1000"), "x").unwrap_err(),
            Error::InvalidKeystore("n is not a power of two")
        );
        assert_eq!(
            decrypt("{", "x").unwrap_err(),
            Error::InvalidKeystore("malformed JSON")
        );
    }
}
