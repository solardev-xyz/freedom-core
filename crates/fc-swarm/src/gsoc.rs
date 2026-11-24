//! GSOC signer mining (design 0015, "Messaging and GSOC mining"): bee-js
//! 13.2.0's `gsocMine` (`modules/messaging.js`), exactly. The candidates
//! are the private keys `0xb33 + i` for `i` below 65,535, in order; the
//! first whose SOC address, `keccak256(identifier ‖ owner)`, shares at least
//! `proximity` leading bits with the target wins. None is a failure. Same
//! inputs, same signer, so every existing room keeps its address.
//!
//! A mined key is public by construction: anyone mines the same one from
//! the same inputs, and it holds nothing of the vault.
//!
//! **Bounded work:** [`Miner::step`] tries at most `n` candidates a call
//! and keeps its place, so a caller can check a deadline or a cancel
//! between batches. Each candidate costs the same: one point addition (the
//! next key's point is the last one's plus the generator), its share of one
//! batched inversion, and two Keccak hashes. [`mine`] is the same search in
//! one call.

use fc_evm::keccak256;
use k256::elliptic_curve::BatchNormalize;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, Scalar, ecdsa::SigningKey};

use crate::Error;
use crate::verify::soc_address;

/// The first candidate key.
pub const KEY_START: u64 = 0xb33;
/// How many candidates bee-js tries: `i` from 0 below `0xffff`.
pub const CANDIDATES: u32 = 0xffff;
/// The mining lane's batch (design 0015, Budgets).
pub const BATCH: u32 = 256;
/// The points converted to affine coordinates with one inversion.
const GROUP: usize = 32;

/// The number of leading bits `a` and `b` share, 0 to 256 (cafe-utility's
/// `Binary.proximity`).
pub fn proximity(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        let diff = x ^ y;
        if diff != 0 {
            return i as u32 * 8 + diff.leading_zeros();
        }
    }
    256
}

/// The mined signer: the `index`th candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signer {
    index: u32,
    owner: [u8; 20],
    soc_address: [u8; 32],
}

impl Signer {
    /// The candidate's place in the search: its key is `0xb33 + index`.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The key as 32 bytes big-endian, as bee-js's `PrivateKey` holds it.
    /// Public by construction (see the module's note), so not a secret.
    pub fn key_bytes(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[24..].copy_from_slice(&(KEY_START + u64::from(self.index)).to_be_bytes());
        key
    }

    /// The key, to sign the GSOC message with ([`crate::sign_soc`]).
    pub fn signing_key(&self) -> Result<SigningKey, Error> {
        SigningKey::from_slice(&self.key_bytes()).map_err(|_| Error::Signing)
    }

    /// The key's address: the SOC's owner.
    pub fn owner(&self) -> [u8; 20] {
        self.owner
    }

    /// `keccak256(identifier ‖ owner)`, the address a message goes to and a
    /// subscription listens on.
    pub fn soc_address(&self) -> [u8; 32] {
        self.soc_address
    }
}

/// What a [`Miner::step`] came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// A candidate matched.
    Found(Signer),
    /// None of the candidates tried so far matched, and some are left.
    More,
    /// All 65,535 candidates were tried and none matched.
    Exhausted,
}

/// bee-js's search, resumable: it holds the next candidate and its point.
#[derive(Debug, Clone)]
pub struct Miner {
    target: [u8; 32],
    identifier: [u8; 32],
    proximity: u32,
    next: u32,
    point: ProjectivePoint,
    found: Option<Signer>,
}

impl Miner {
    /// A search for the signer of `identifier`'s SOC nearest `target`,
    /// within `proximity` bits (bee-js's default is 12; past 256 nothing
    /// matches).
    pub fn new(target: &[u8; 32], identifier: &[u8; 32], proximity: u32) -> Self {
        Self {
            target: *target,
            identifier: *identifier,
            proximity,
            next: 0,
            point: ProjectivePoint::GENERATOR * Scalar::from(KEY_START),
            found: None,
        }
    }

    /// The candidates tried so far.
    pub fn tried(&self) -> u32 {
        match self.found {
            Some(signer) => signer.index + 1,
            None => self.next,
        }
    }

    /// Tries at most `n` more candidates, in order, stopping at the first
    /// match. Once it has found the signer or tried all 65,535, it tries
    /// nothing more and answers the same.
    pub fn step(&mut self, n: u32) -> Step {
        if let Some(signer) = self.found {
            return Step::Found(signer);
        }
        let end = self.next.saturating_add(n).min(CANDIDATES);
        while self.next < end {
            let count = ((end - self.next) as usize).min(GROUP);
            let mut points = [ProjectivePoint::IDENTITY; GROUP];
            for point in points.iter_mut().take(count) {
                *point = self.point;
                self.point += ProjectivePoint::GENERATOR;
            }
            let affine = ProjectivePoint::batch_normalize(&points);
            for (j, point) in affine.iter().take(count).enumerate() {
                let encoded = point.to_sec1_point(false);
                let hash = keccak256(encoded.as_bytes().get(1..).unwrap_or_default());
                let mut owner = [0u8; 20];
                owner.copy_from_slice(&hash[12..]);
                let soc_address = soc_address(&self.identifier, &owner);
                if proximity(&soc_address, &self.target) >= self.proximity {
                    let signer = Signer {
                        index: self.next + j as u32,
                        owner,
                        soc_address,
                    };
                    self.found = Some(signer);
                    return Step::Found(signer);
                }
            }
            self.next += count as u32;
        }
        if self.next == CANDIDATES {
            Step::Exhausted
        } else {
            Step::More
        }
    }
}

/// The whole search in one call: the signer, or none in 65,535 candidates
/// (bee-js's `Could not mine a valid signer`).
pub fn mine(target: &[u8; 32], identifier: &[u8; 32], proximity: u32) -> Option<Signer> {
    let mut miner = Miner::new(target, identifier, proximity);
    loop {
        match miner.step(BATCH) {
            Step::Found(signer) => return Some(signer),
            Step::Exhausted => return None,
            Step::More => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn proximity_counts_leading_bits() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        assert_eq!(proximity(&a, &b), 256);
        b[0] = 0x80;
        assert_eq!(proximity(&a, &b), 0);
        b[0] = 0x01;
        assert_eq!(proximity(&a, &b), 7);
        b[0] = 0;
        b[31] = 1;
        assert_eq!(proximity(&a, &b), 255);
    }

    /// Each candidate's owner is its key's address, as a full scalar
    /// multiplication gives it.
    #[test]
    fn candidates_are_the_keys_from_0xb33() {
        let id = [5u8; 32];
        for index in [0u32, 1, 31, 32, 33, 100] {
            let key = Signer {
                index,
                owner: [0; 20],
                soc_address: [0; 32],
            }
            .signing_key()
            .unwrap();
            let owner = fc_evm::address_of(&key);
            let target = soc_address(&id, &owner);
            let signer = mine(&target, &id, 256).unwrap();
            assert_eq!(signer.index(), index);
            assert_eq!(signer.owner(), owner);
        }
    }

    #[test]
    fn proximity_zero_is_the_first_candidate_and_past_256_nothing() {
        let mut miner = Miner::new(&[1; 32], &[2; 32], 0);
        assert!(matches!(miner.step(1), Step::Found(s) if s.index() == 0));
        assert_eq!(miner.tried(), 1);
        let mut miner = Miner::new(&[1; 32], &[2; 32], 257);
        assert_eq!(miner.step(0), Step::More);
        assert_eq!(miner.tried(), 0);
        assert_eq!(miner.step(65_000), Step::More);
        assert_eq!(miner.step(1_000), Step::Exhausted);
        assert_eq!(miner.tried(), CANDIDATES);
        assert_eq!(miner.step(1), Step::Exhausted);
        assert_eq!(miner.tried(), CANDIDATES);
    }
}
