//! HMAC (RFC 2104) and PBKDF2 (RFC 8018) over SHA-2, with every key-derived
//! buffer wiped.
//!
//! The `hmac` 0.13 and `pbkdf2` 0.13 crates leave the HMAC key pads, which
//! hold the key XORed with a public constant, and PBKDF2's per-round outputs
//! in ordinary buffers that are never cleared (Codex's review of PR #3). This
//! module is the same pair of algorithms with those buffers in `Zeroizing`.
//! The SHA-2 states wipe themselves through sha2's `zeroize` feature. Tests
//! compare against both crates.

use sha2::Digest;
use sha2::digest::Output;
use sha2::digest::block_api::BlockSizeUser;
use zeroize::Zeroizing;

/// The largest SHA-2 block (SHA-512).
const MAX_BLOCK: usize = 128;

/// HMAC over a SHA-2 hash `D`, keyed once and cloned for each message.
#[derive(Clone)]
pub struct Hmac<D: Digest + BlockSizeUser + Clone> {
    inner: D,
    outer: D,
}

impl<D: Digest + BlockSizeUser + Clone> Hmac<D> {
    pub fn new(key: &[u8]) -> Self {
        let block = D::block_size();
        debug_assert!(block <= MAX_BLOCK);
        let block = block.min(MAX_BLOCK);

        let mut padded_key = Zeroizing::new([0u8; MAX_BLOCK]);
        if key.len() > block {
            let mut hashed = Zeroizing::new(Output::<D>::default());
            let mut hasher = D::new();
            Digest::update(&mut hasher, key);
            hasher.finalize_into(&mut hashed);
            padded_key[..hashed.len()].copy_from_slice(&hashed);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        let mut pad = Zeroizing::new([0u8; MAX_BLOCK]);
        for (p, k) in pad[..block].iter_mut().zip(&padded_key[..block]) {
            *p = k ^ 0x36;
        }
        let mut inner = D::new();
        Digest::update(&mut inner, &pad[..block]);
        for (p, k) in pad[..block].iter_mut().zip(&padded_key[..block]) {
            *p = k ^ 0x5c;
        }
        let mut outer = D::new();
        Digest::update(&mut outer, &pad[..block]);
        Hmac { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    /// Writes the MAC into `out`, which the caller keeps wiped.
    pub fn finalize_into(self, out: &mut Output<D>) {
        let Hmac { inner, mut outer } = self;
        let mut inner_hash = Zeroizing::new(Output::<D>::default());
        inner.finalize_into(&mut inner_hash);
        Digest::update(&mut outer, inner_hash.as_slice());
        outer.finalize_into(out);
    }
}

/// HMAC-SHA-512 over the concatenation of `parts` (BIP-32, SLIP-10).
pub(crate) fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<sha2::Sha512>::new(key);
    for part in parts {
        mac.update(part);
    }
    let mut output = Zeroizing::new(Output::<sha2::Sha512>::default());
    mac.finalize_into(&mut output);
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&output);
    out
}

/// PBKDF2 with HMAC over `D`, filling `out`.
pub fn pbkdf2<D: Digest + BlockSizeUser + Clone>(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    out: &mut [u8],
) {
    let prf = Hmac::<D>::new(password);
    let mut u = Zeroizing::new(Output::<D>::default());
    let mut t = Zeroizing::new(Output::<D>::default());
    for (index, chunk) in out.chunks_mut(u.len()).enumerate() {
        // Block indices start at 1; `out` is never long enough to overflow.
        let block_index = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        mac.finalize_into(&mut u);
        t.copy_from_slice(&u);
        for _ in 1..rounds {
            let mut mac = prf.clone();
            mac.update(&u);
            mac.finalize_into(&mut u);
            for (t, u) in t.iter_mut().zip(u.iter()) {
                *t ^= u;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{KeyInit, Mac};
    use sha2::{Sha256, Sha512};

    /// Deterministic pseudo-random bytes for differential tests.
    fn bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    fn ours<D: Digest + BlockSizeUser + Clone>(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<D>::new(key);
        mac.update(msg);
        let mut out = Output::<D>::default();
        mac.finalize_into(&mut out);
        out.to_vec()
    }

    #[test]
    fn hmac_matches_the_hmac_crate() {
        // Keys shorter than, equal to and longer than both block sizes.
        for (seed, key_len) in [0usize, 1, 20, 63, 64, 65, 127, 128, 129, 300]
            .into_iter()
            .enumerate()
        {
            let key = bytes(seed as u64, key_len);
            let msg = bytes(1000 + seed as u64, seed * 37);
            let mut reference = hmac::Hmac::<Sha512>::new_from_slice(&key).unwrap();
            reference.update(&msg);
            assert_eq!(
                ours::<Sha512>(&key, &msg),
                reference.finalize().into_bytes().to_vec()
            );
            let mut reference = hmac::Hmac::<Sha256>::new_from_slice(&key).unwrap();
            reference.update(&msg);
            assert_eq!(
                ours::<Sha256>(&key, &msg),
                reference.finalize().into_bytes().to_vec()
            );
        }
    }

    #[test]
    fn hmac_rfc4231_case_1() {
        let key = [0x0b; 20];
        assert_eq!(
            hex::encode(ours::<Sha256>(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(ours::<Sha512>(&key, b"Hi There")),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn pbkdf2_matches_the_pbkdf2_crate() {
        for (seed, (rounds, out_len)) in
            [(1u32, 32usize), (2, 64), (3, 100), (1000, 32), (2048, 64)]
                .into_iter()
                .enumerate()
        {
            let password = bytes(seed as u64, 5 + seed * 30);
            let salt = bytes(500 + seed as u64, 8 + seed * 4);
            let mut a = vec![0u8; out_len];
            let mut b = vec![0u8; out_len];
            pbkdf2::<Sha512>(&password, &salt, rounds, &mut a);
            pbkdf2::pbkdf2_hmac::<Sha512>(&password, &salt, rounds, &mut b);
            assert_eq!(a, b, "sha512 rounds={rounds} len={out_len}");
            pbkdf2::<Sha256>(&password, &salt, rounds, &mut a);
            pbkdf2::pbkdf2_hmac::<Sha256>(&password, &salt, rounds, &mut b);
            assert_eq!(a, b, "sha256 rounds={rounds} len={out_len}");
        }
    }
}
