//! SLIP-10 Ed25519 derivation, matching `micro-key-producer/slip10.js`
//! (`HDKey.fromMasterSeed(seed).derive(path)`).

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::{DerivationPath, Error, Seed};

type HmacSha512 = Hmac<Sha512>;

/// A derived Ed25519 key. Zeroizes on drop and never prints its secret.
pub struct Ed25519Key {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    path: DerivationPath,
}

/// Derives the Ed25519 key at `path` (all segments hardened) from `seed`.
pub fn derive_ed25519(seed: &Seed, path: &DerivationPath) -> Result<Ed25519Key, Error> {
    derive_from_seed_bytes(seed.as_bytes(), path)
}

fn derive_from_seed_bytes(seed: &[u8], path: &DerivationPath) -> Result<Ed25519Key, Error> {
    let (mut key, mut chain_code) = split(hmac(b"ed25519 seed", &[seed])?);
    for child in path.children() {
        if !child.is_hardened() {
            return Err(Error::NonHardenedEd25519);
        }
        (key, chain_code) = split(hmac(
            chain_code.as_slice(),
            &[&[0u8], key.as_slice(), &child.to_be_bytes()],
        )?);
    }
    let public = ed25519_dalek::SigningKey::from_bytes(&key)
        .verifying_key()
        .to_bytes();
    Ok(Ed25519Key {
        secret: key,
        public,
        path: path.clone(),
    })
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| Error::Derivation)?;
    for part in parts {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

fn split(i: Zeroizing<[u8; 64]>) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut left = Zeroizing::new([0u8; 32]);
    let mut right = Zeroizing::new([0u8; 32]);
    left.copy_from_slice(&i[..32]);
    right.copy_from_slice(&i[32..]);
    (left, right)
}

impl Ed25519Key {
    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    /// The raw 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The raw 32-byte private key (the Ed25519 seed). For key-file encoders
    /// and the temporary `compat.*` exports only.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.secret)
    }
}

impl fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Key")
            .field("path", &self.path.to_string())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SLIP-10 test vector 1 for ed25519, seed 000102…0f. The values were
    /// confirmed with micro-key-producer (see the PR description).
    #[test]
    fn slip10_vector_1() {
        // The vector uses a 16-byte seed; `Seed` is always 64 bytes.
        let raw = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let cases = [
            (
                "m/0'",
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
            ),
            (
                "m/0'/1'",
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
            ),
            (
                "m/0'/1'/2'",
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
            ),
        ];
        for (path, secret, public) in cases {
            let key = derive_from_seed_bytes(&raw, &path.parse().unwrap()).unwrap();
            assert_eq!(
                hex::encode(key.to_secret_bytes().as_slice()),
                secret,
                "{path}"
            );
            assert_eq!(hex::encode(key.public_key()), public, "{path}");
        }
    }

    #[test]
    fn rejects_non_hardened() {
        let seed = crate::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
        .to_seed();
        assert_eq!(
            derive_ed25519(&seed, &"m/44'/0".parse().unwrap()).unwrap_err(),
            Error::NonHardenedEd25519
        );
    }
}
