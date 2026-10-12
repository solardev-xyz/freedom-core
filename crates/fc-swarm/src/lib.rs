//! Swarm single-owner chunks (design 0002, `swarm.sign_soc`), byte-for-byte
//! as bee-js 13 builds them with `makeContentAddressedChunk(payload, span)
//! .toSingleOwnerChunk(identifier, key)`. `vectors/signing.json` is the
//! contract. The crate does no I/O.
//!
//! The chunk address is computed here from the payload, so a caller can only
//! get genuine SOC digests signed, never an arbitrary 32-byte value.

use fc_evm::{address_of, keccak256, sign_message};
use k256::ecdsa::SigningKey;

/// The largest chunk payload.
pub const CHUNK_SIZE: usize = 4096;
const SEGMENT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("payload size {0} outside 1..=4096")]
    PayloadSize(usize),
    #[error("signing failed")]
    Signing,
}

/// The root of Swarm's binary Merkle tree over the payload, zero-padded to
/// 4096 bytes: 128 segments of 32 bytes, hashed pairwise with keccak256.
pub fn bmt_root(payload: &[u8]) -> Result<[u8; 32], Error> {
    if payload.is_empty() || payload.len() > CHUNK_SIZE {
        return Err(Error::PayloadSize(payload.len()));
    }
    let mut level = vec![0u8; CHUNK_SIZE];
    level[..payload.len()].copy_from_slice(payload);
    while level.len() > SEGMENT {
        level = level.chunks(2 * SEGMENT).flat_map(keccak256).collect();
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&level);
    Ok(root)
}

/// A content-addressed chunk's address: keccak256(span as 8 bytes little
/// endian ‖ BMT root).
pub fn chunk_address(span: u64, payload: &[u8]) -> Result<[u8; 32], Error> {
    let mut data = [0u8; 40];
    data[..8].copy_from_slice(&span.to_le_bytes());
    data[8..].copy_from_slice(&bmt_root(payload)?);
    Ok(keccak256(&data))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedChunk {
    pub span: u64,
    pub chunk_address: [u8; 32],
    /// 65 bytes `r ‖ s ‖ v`, `v ∈ {27, 28}`.
    pub signature: [u8; 65],
    pub owner: [u8; 20],
    pub soc_address: [u8; 32],
}

/// Signs a single-owner chunk. `span` defaults to the payload length; as in
/// bee-js, a span of 0 also means the payload length.
pub fn sign_soc(
    key: &SigningKey,
    identifier: &[u8; 32],
    span: Option<u64>,
    payload: &[u8],
) -> Result<SignedChunk, Error> {
    let span = match span {
        Some(span) if span != 0 => span,
        _ => payload.len() as u64,
    };
    let chunk_address = chunk_address(span, payload)?;
    let mut digest_input = [0u8; 64];
    digest_input[..32].copy_from_slice(identifier);
    digest_input[32..].copy_from_slice(&chunk_address);
    // EIP-191 over the 32-byte digest, as bee-js' PrivateKey.sign does.
    let signature = sign_message(key, &keccak256(&digest_input)).map_err(|_| Error::Signing)?;
    let owner = address_of(key);
    let mut soc_input = [0u8; 52];
    soc_input[..32].copy_from_slice(identifier);
    soc_input[32..].copy_from_slice(&owner);
    Ok(SignedChunk {
        span,
        chunk_address,
        signature,
        owner,
        soc_address: keccak256(&soc_input),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_bounds() {
        assert_eq!(bmt_root(&[]), Err(Error::PayloadSize(0)));
        assert_eq!(bmt_root(&[0; 4097]), Err(Error::PayloadSize(4097)));
        assert!(bmt_root(&[0; 4096]).is_ok());
    }
}
