//! A Safe's owners and threshold, its address and its deployment (design
//! 0016, "Built and hashed in the core"), as the reference's
//! `pinnedDeployment` computes them (`safe-executor.js`), with no chain
//! read.

use fc_evm::{U256, checksum_address, keccak256};
use fc_naming::abi::Token;

use crate::constants::{CHAIN_ID, FALLBACK_HANDLER, PROXY_CREATION_CODE, PROXY_FACTORY, SINGLETON};
use crate::{Error, address_word, call};

/// The owners' list sentinel of Safe's `OwnerManager`, which `setup`
/// refuses as an owner.
const SENTINEL: [u8; 20] = {
    let mut sentinel = [0u8; 20];
    sentinel[19] = 1;
    sentinel
};

/// A Safe's owners, in the record's order, and its threshold: 1 of 2 or 2
/// of 3, as Freedom creates them (Q24; the record's own check is
/// fc-wallet-state's `add_safe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    owners: Vec<[u8; 20]>,
    threshold: usize,
}

impl Setup {
    /// Refuses another count or threshold ([`Error::Unsupported`]), and an
    /// owner list Safe's `setup` would revert on ([`Error::Owners`]).
    pub fn new(owners: Vec<[u8; 20]>, threshold: usize) -> Result<Self, Error> {
        if !matches!((owners.len(), threshold), (2, 1) | (3, 2)) {
            return Err(Error::Unsupported("not 1 of 2 or 2 of 3 owners"));
        }
        for (i, owner) in owners.iter().enumerate() {
            if *owner == [0u8; 20] || *owner == SENTINEL {
                return Err(Error::Owners("the zero address or the sentinel"));
            }
            if owners[..i].contains(owner) {
                return Err(Error::Owners("an owner twice"));
            }
        }
        Ok(Setup { owners, threshold })
    }

    /// The owners, in the record's order.
    pub fn owners(&self) -> &[[u8; 20]] {
        &self.owners
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// `setup(owners, threshold, 0x0, 0x, handler, 0x0, 0, 0x0)`: no setup
    /// call, the canonical fallback handler, no payment.
    pub fn initializer(&self) -> Vec<u8> {
        let owners: Vec<[u8; 32]> = self.owners.iter().map(address_word).collect();
        call(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            &[
                Token::Words(&owners),
                Token::Word(U256::from_u64(self.threshold as u64).to_be_bytes()),
                Token::Word([0; 32]),
                Token::Dynamic(&[]),
                Token::Word(address_word(&FALLBACK_HANDLER)),
                Token::Word([0; 32]),
                Token::Word([0; 32]),
                Token::Word([0; 32]),
            ],
        )
    }

    /// The address the factory deploys this Safe at, with `salt`: CREATE2
    /// from the factory, salt keccak256(keccak256(initializer) ‖ salt), init
    /// code the proxy code ‖ the singleton as a word.
    pub fn address(&self, salt: &U256) -> [u8; 20] {
        self.address_of(&self.initializer(), salt)
    }

    fn address_of(&self, initializer: &[u8], salt: &U256) -> [u8; 20] {
        let mut salted = keccak256(initializer).to_vec();
        salted.extend(salt.to_be_bytes());
        let mut init_code = PROXY_CREATION_CODE.to_vec();
        init_code.extend(address_word(&SINGLETON));
        let mut preimage = vec![0xff];
        preimage.extend(PROXY_FACTORY);
        preimage.extend(keccak256(&salted));
        preimage.extend(keccak256(&init_code));
        let hash = keccak256(&preimage);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    /// The deployment: `createProxyWithNonce(singleton, initializer, salt)`
    /// to the factory, value 0, and the address it lands on.
    pub fn deployment(&self, salt: &U256) -> Deployment {
        let initializer = self.initializer();
        let data = call(
            "createProxyWithNonce(address,bytes,uint256)",
            &[
                Token::Word(address_word(&SINGLETON)),
                Token::Dynamic(&initializer),
                Token::Word(salt.to_be_bytes()),
            ],
        );
        Deployment {
            safe: self.address_of(&initializer, salt),
            to: PROXY_FACTORY,
            data,
        }
    }

    /// Refuses a record whose stored address isn't this Safe's
    /// ([`Error::AddressMismatch`]): what the record was shown with, and
    /// funds may have gone to, is the address its init params derive.
    pub fn check_address(&self, salt: &U256, record: &[u8; 20]) -> Result<(), Error> {
        let derived = self.address(salt);
        if derived == *record {
            Ok(())
        } else {
            Err(Error::AddressMismatch {
                record: checksum_address(record),
                derived: checksum_address(&derived),
            })
        }
    }
}

/// A Safe's deployment transaction: to the factory, value 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    /// The address it creates.
    pub safe: [u8; 20],
    /// The factory.
    pub to: [u8; 20],
    pub data: Vec<u8>,
}

/// A Safe record's salt: decimal digits (leading zeros allowed, as
/// `BigInt` reads them) for a uint256.
pub fn parse_salt(text: &str) -> Result<U256, Error> {
    U256::parse_decimal(text).ok_or(Error::Salt)
}

/// Refuses any chain but Gnosis ([`Error::Unsupported`]).
pub fn check_chain(chain_id: &U256) -> Result<(), Error> {
    if chain_id.to_u64() == Some(CHAIN_ID) {
        Ok(())
    } else {
        Err(Error::Unsupported("another chain than Gnosis"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const A: [u8; 20] = [0xa1; 20];
    const B: [u8; 20] = [0xb2; 20];
    const C: [u8; 20] = [0xc3; 20];

    #[test]
    fn only_one_of_two_and_two_of_three() {
        assert!(Setup::new(vec![A, B], 1).is_ok());
        assert!(Setup::new(vec![A, B, C], 2).is_ok());
        for (owners, threshold) in [
            (vec![], 0),
            (vec![], 1),
            (vec![A], 1),
            (vec![A, B], 0),
            (vec![A, B], 2),
            (vec![A, B], 3),
            (vec![A, B, C], 1),
            (vec![A, B, C], 3),
            (vec![A, B, C, [0xd4; 20]], 2),
        ] {
            assert_eq!(
                Setup::new(owners.clone(), threshold)
                    .map(|_| ())
                    .map_err(|e| e.kind()),
                Err("unsupported"),
                "{} owners, threshold {threshold}",
                owners.len()
            );
        }
    }

    #[test]
    fn owners_setup_would_refuse_are_refused() {
        for owners in [
            vec![A, A],
            vec![A, B, A],
            vec![A, [0; 20]],
            vec![SENTINEL, A],
        ] {
            let threshold = owners.len() - 1;
            assert_eq!(
                Setup::new(owners, threshold)
                    .map(|_| ())
                    .map_err(|e| e.kind()),
                Err("owners")
            );
        }
    }

    #[test]
    fn a_salt_is_decimal_digits_for_a_uint256() {
        assert_eq!(parse_salt("0"), Ok(U256::ZERO));
        assert_eq!(parse_salt("007"), Ok(U256::from_u64(7)));
        assert_eq!(parse_salt(&U256::MAX.to_decimal()), Ok(U256::MAX));
        let past = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        for bad in ["", "-1", "+1", "0x10", "1.5", " 1", "1 ", "1e3", past] {
            assert_eq!(parse_salt(bad), Err(Error::Salt), "{bad:?}");
        }
    }

    #[test]
    fn the_deployment_lands_on_the_address() {
        let setup = Setup::new(vec![A, B, C], 2).unwrap();
        for salt in [U256::ZERO, U256::from_u64(1), U256::MAX] {
            let deployment = setup.deployment(&salt);
            assert_eq!(deployment.safe, setup.address(&salt));
            assert_eq!(deployment.to, PROXY_FACTORY);
            assert!(setup.check_address(&salt, &deployment.safe).is_ok());
        }
        let other = Setup::new(vec![B, A, C], 2).unwrap();
        assert_ne!(other.address(&U256::ZERO), setup.address(&U256::ZERO));
        assert_eq!(
            other
                .check_address(&U256::ZERO, &setup.address(&U256::ZERO))
                .map_err(|e| e.kind()),
            Err("address_mismatch")
        );
    }

    #[test]
    fn only_gnosis() {
        assert!(check_chain(&U256::from_u64(100)).is_ok());
        for chain in [0, 1, 99, 101, 10_100] {
            assert!(check_chain(&U256::from_u64(chain)).is_err(), "{chain}");
        }
        let mut wide = [0u8; 32];
        wide[0] = 1;
        wide[31] = 100;
        assert!(check_chain(&U256::from_be_slice(&wide).unwrap()).is_err());
    }
}
