//! Freedom's derivation paths, as in freedom-browser's
//! `src/main/identity/derivation.js` (`PATHS`, `deriveAllKeys`,
//! `deriveUserWallet`, `derivePublisherKey`).

use crate::{
    ChildIndex, DerivationPath, Ed25519Key, Error, Secp256k1Key, Seed, derive_ed25519,
    derive_secp256k1,
};

/// Bee (Swarm node) wallet: BIP-44 account 0, address index 1.
pub const BEE_WALLET: &str = "m/44'/60'/0'/0/1";
/// Radicle node key (did:key), SLIP-10 Ed25519.
pub const RADICLE: &str = "m/44'/73404'/0'/0'/0'";
/// IPFS PeerID key, SLIP-10 Ed25519.
pub const IPFS: &str = "m/44'/73405'/0'/0'/0'";

/// `m/44'/60'/{account}'/0/0`: the user's wallet accounts.
pub fn user_wallet_path(account: u32) -> Result<DerivationPath, Error> {
    bip44(60, account)
}

/// `m/44'/73406'/{origin}'/0/0`: per-origin Swarm publisher keys.
pub fn publisher_path(origin: u32) -> Result<DerivationPath, Error> {
    bip44(73406, origin)
}

fn bip44(coin_type: u32, account: u32) -> Result<DerivationPath, Error> {
    Ok([
        ChildIndex::hardened(44)?,
        ChildIndex::hardened(coin_type)?,
        ChildIndex::hardened(account)?,
        ChildIndex::normal(0)?,
        ChildIndex::normal(0)?,
    ]
    .into_iter()
    .collect())
}

/// The keys `deriveAllKeys` returns.
#[derive(Debug)]
pub struct FreedomKeys {
    pub user_wallet: Secp256k1Key,
    pub bee_wallet: Secp256k1Key,
    pub radicle: Ed25519Key,
    pub ipfs: Ed25519Key,
}

pub fn derive_all(seed: &Seed) -> Result<FreedomKeys, Error> {
    Ok(FreedomKeys {
        user_wallet: derive_user_wallet(seed, 0)?,
        bee_wallet: derive_secp256k1(seed, &BEE_WALLET.parse()?)?,
        radicle: derive_ed25519(seed, &RADICLE.parse()?)?,
        ipfs: derive_ed25519(seed, &IPFS.parse()?)?,
    })
}

pub fn derive_user_wallet(seed: &Seed, account: u32) -> Result<Secp256k1Key, Error> {
    derive_secp256k1(seed, &user_wallet_path(account)?)
}

pub fn derive_publisher(seed: &Seed, origin: u32) -> Result<Secp256k1Key, Error> {
    derive_secp256k1(seed, &publisher_path(origin)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(user_wallet_path(0).unwrap().to_string(), "m/44'/60'/0'/0/0");
        assert_eq!(
            publisher_path(7).unwrap().to_string(),
            "m/44'/73406'/7'/0/0"
        );
        assert_eq!(
            user_wallet_path((1 << 31) - 1).unwrap().to_string(),
            "m/44'/60'/2147483647'/0/0"
        );
        assert_eq!(
            user_wallet_path(1 << 31).unwrap_err(),
            Error::IndexOutOfRange(1 << 31)
        );
        assert_eq!(
            publisher_path(u32::MAX).unwrap_err(),
            Error::IndexOutOfRange(u64::from(u32::MAX))
        );
    }
}
