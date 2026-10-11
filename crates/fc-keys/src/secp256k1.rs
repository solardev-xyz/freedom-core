//! BIP-32 secp256k1 derivation and Ethereum addresses, matching ethers v6's
//! `HDNodeWallet.fromMnemonic(…, path)`.
//!
//! BIP-32 is implemented here on `k256` rather than taken from a crate, so
//! every intermediate private key and chain code is zeroized.

use std::fmt;

use hmac::{Hmac, Mac};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{NonZeroScalar, Scalar, SecretKey};
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::{ChildIndex, DerivationPath, Error, Seed};

type HmacSha512 = Hmac<Sha512>;

/// A derived secp256k1 key. Zeroizes on drop and never prints its secret.
pub struct Secp256k1Key {
    key: k256::ecdsa::SigningKey,
    path: DerivationPath,
}

/// A 20-byte Ethereum address. `Display` gives the EIP-55 checksummed form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 20]);

/// Derives the secp256k1 key at `path` from `seed` (BIP-32).
pub fn derive_secp256k1(seed: &Seed, path: &DerivationPath) -> Result<Secp256k1Key, Error> {
    derive_from_seed_bytes(seed.as_bytes(), path)
}

fn derive_from_seed_bytes(seed: &[u8], path: &DerivationPath) -> Result<Secp256k1Key, Error> {
    let i = hmac(b"Bitcoin seed", &[seed])?;
    let mut key = secret_from(&i[..32])?;
    let mut chain_code = chain_code_from(&i);
    for child in path.children() {
        (key, chain_code) = derive_child(&key, &chain_code, *child)?;
    }
    Ok(Secp256k1Key {
        key: k256::ecdsa::SigningKey::from(&key),
        path: path.clone(),
    })
}

/// BIP-32 `CKDpriv`.
fn derive_child(
    parent: &SecretKey,
    chain_code: &[u8; 32],
    child: ChildIndex,
) -> Result<(SecretKey, Zeroizing<[u8; 32]>), Error> {
    let i = if child.is_hardened() {
        let parent_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(parent.to_bytes().into());
        hmac(
            chain_code,
            &[&[0u8], parent_bytes.as_slice(), &child.to_be_bytes()],
        )?
    } else {
        let public = parent.public_key().to_encoded_point(true);
        hmac(chain_code, &[public.as_bytes(), &child.to_be_bytes()])?
    };
    let tweak = scalar_from(&i[..32])?;
    let sum = tweak + parent.to_nonzero_scalar().as_ref();
    let child_key = Option::<NonZeroScalar>::from(NonZeroScalar::new(sum))
        .map(SecretKey::from)
        .ok_or(Error::Derivation)?;
    Ok((child_key, chain_code_from(&i)))
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

/// `parse256(IL)`, rejecting values `>= n` as BIP-32 requires.
fn scalar_from(bytes: &[u8]) -> Result<Scalar, Error> {
    let mut repr = k256::FieldBytes::default();
    repr.copy_from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_repr(repr)).ok_or(Error::Derivation)
}

fn secret_from(bytes: &[u8]) -> Result<SecretKey, Error> {
    SecretKey::from_slice(bytes).map_err(|_| Error::Derivation)
}

fn chain_code_from(i: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    let mut chain_code = Zeroizing::new([0u8; 32]);
    chain_code.copy_from_slice(&i[32..]);
    chain_code
}

impl Secp256k1Key {
    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    /// SEC1 compressed public key (33 bytes), as ethers' `publicKey`.
    pub fn public_key(&self) -> [u8; 33] {
        let point = self.key.verifying_key().as_affine().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// SEC1 uncompressed public key (65 bytes, `0x04` prefix).
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let point = self.key.verifying_key().as_affine().to_encoded_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    pub fn address(&self) -> Address {
        let uncompressed = self.public_key_uncompressed();
        let hash = Keccak256::digest(&uncompressed[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        Address(address)
    }

    /// The signing key, for signing inside the core.
    pub fn signing_key(&self) -> &k256::ecdsa::SigningKey {
        &self.key
    }

    /// The raw 32-byte private key. Only for the temporary `compat.*`
    /// exports, the user-requested export, and keystore encoding.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes().into())
    }
}

impl fmt::Debug for Secp256k1Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secp256k1Key")
            .field("path", &self.path.to_string())
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

impl Address {
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// EIP-55 mixed-case checksum encoding with `0x` prefix.
    pub fn to_checksum(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut lower = [0u8; 40];
        for (i, byte) in self.0.iter().enumerate() {
            lower[2 * i] = HEX[usize::from(byte >> 4)];
            lower[2 * i + 1] = HEX[usize::from(byte & 0x0f)];
        }
        let hash = Keccak256::digest(lower);
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, c) in lower.iter().enumerate() {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
                char::from(c.to_ascii_uppercase())
            } else {
                char::from(*c)
            });
        }
        out
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_checksum())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_checksum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mnemonic;

    #[test]
    fn ethers_reference_account_zero() {
        // From ethers 6 (freedom-browser's node_modules), see the PR description.
        let seed = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
        .to_seed();
        let key = derive_secp256k1(&seed, &"m/44'/60'/0'/0/0".parse().unwrap()).unwrap();
        assert_eq!(
            key.address().to_string(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(
            hex::encode(key.to_secret_bytes().as_slice()),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
        assert_eq!(
            hex::encode(key.public_key()),
            "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"
        );
        let debug = format!("{key:?}");
        assert!(
            !debug.contains("1ab42cc4"),
            "Debug must not print the secret: {debug}"
        );
    }

    /// BIP-32 test vectors 1–3. Expected keys confirmed with ethers 6
    /// (`HDNodeWallet.fromSeed(seed).derivePath(path)`).
    #[test]
    fn bip32_vectors() {
        let v1 = "000102030405060708090a0b0c0d0e0f";
        let v2 = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        let v3 = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";
        let cases = [
            (
                v1,
                "m",
                "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
            ),
            (
                v1,
                "m/0'",
                "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
            ),
            (
                v1,
                "m/0'/1",
                "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
            ),
            (
                v1,
                "m/0'/1/2'",
                "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
            ),
            (
                v1,
                "m/0'/1/2'/2",
                "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
            ),
            (
                v1,
                "m/0'/1/2'/2/1000000000",
                "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
            ),
            (
                v2,
                "m",
                "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
                "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
            ),
            (
                v2,
                "m/0",
                "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
                "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
            ),
            (
                v2,
                "m/0/2147483647'",
                "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
                "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
            ),
            (
                v2,
                "m/0/2147483647'/1",
                "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
                "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
            ),
            (
                v2,
                "m/0/2147483647'/1/2147483646'",
                "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
                "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
            ),
            (
                v2,
                "m/0/2147483647'/1/2147483646'/2",
                "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
                "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
            ),
            (
                v3,
                "m",
                "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
                "03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669",
            ),
            (
                v3,
                "m/0'",
                "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
                "026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2",
            ),
        ];
        for (seed, path, secret, public) in cases {
            let key = derive_from_seed_bytes(&hex::decode(seed).unwrap(), &path.parse().unwrap())
                .unwrap();
            assert_eq!(
                hex::encode(key.to_secret_bytes().as_slice()),
                secret,
                "{path}"
            );
            assert_eq!(hex::encode(key.public_key()), public, "{path}");
        }
    }

    #[test]
    fn eip55_spec_examples() {
        for expected in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let mut bytes = [0u8; 20];
            hex::decode_to_slice(&expected[2..], &mut bytes).unwrap();
            assert_eq!(Address::from_bytes(bytes).to_checksum(), expected);
        }
    }
}
