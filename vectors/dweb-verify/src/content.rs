//! Fixture content, from a seed.

use sha2::{Digest, Sha256};

/// `len` bytes of content for `seed`: SHA-256(seed ‖ u64_be(i)) for
/// i = 0, 1, 2, …, concatenated and cut to `len`. Any reader can rebuild
/// it, so the vectors hold seeds and lengths, not file bodies.
pub fn bytes(seed: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut i: u64 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(i.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        i += 1;
    }
    out.truncate(len);
    out
}
