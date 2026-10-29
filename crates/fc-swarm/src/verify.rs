//! Checks on the pieces an external Swarm node serves (design 0009,
//! Chunks, Manifests and feeds, Leaves), as Ant v0.5.71 reads them.
//! `vectors/dweb-verify-cases.json` (swarm) is the contract; beside each
//! case it records Ant's own `cac_valid` and `soc_valid` on the same bytes.
//!
//! Nothing here allocates: a checked piece is a view into its wire bytes.

use fc_evm::{eip191_digest, keccak256, recover_address};

use crate::CHUNK_SIZE;

/// A chunk's span: 8 bytes, little-endian; an erasure-coded intermediate
/// chunk carries its level in the top byte.
pub const SPAN_SIZE: usize = 8;
/// The largest content-addressed chunk on the wire.
pub const MAX_CHUNK_WIRE: usize = SPAN_SIZE + CHUNK_SIZE;
const SOC_ID: usize = 32;
const SOC_SIGNATURE: usize = 65;
const SOC_HEADER: usize = SOC_ID + SOC_SIGNATURE;
/// The published key Bee signs dispersed replicas with (ethersphere/bee#5640).
pub const REPLICAS_OWNER: [u8; 20] = [
    0xdc, 0x5b, 0x20, 0x84, 0x7f, 0x43, 0xd6, 0x79, 0x28, 0xf4, 0x9c, 0xd4, 0xf8, 0x5d, 0x69, 0x6b,
    0x5a, 0x76, 0x17, 0xb5,
];

/// Why a piece is refused (0009, Failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The bytes aren't what their address or signature commits to.
    VerificationFailed,
    /// Authentic, or possibly so, but outside what the core checks: a
    /// single-owner chunk where a content-addressed one is needed, an
    /// encrypted reference, a leaf shorter than its logical length.
    Unverifiable,
}

/// A content-addressed chunk that passed its check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    /// The span as sent, level byte included.
    pub span: [u8; SPAN_SIZE],
    pub payload: &'a [u8],
}

/// The BMT root of a payload of 0 to 4096 bytes, zero-padded to 4096. The
/// empty payload is valid here: the empty chunk is an empty file's
/// reference. ([`crate::bmt_root`], for signing, refuses it.)
pub fn bmt_root_of(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.len() > CHUNK_SIZE {
        return None;
    }
    let mut level = [0u8; CHUNK_SIZE];
    level[..payload.len()].copy_from_slice(payload);
    let mut len = CHUNK_SIZE;
    while len > 32 {
        for i in 0..len / 64 {
            let h = keccak256(&level[i * 64..i * 64 + 64]);
            level[i * 32..i * 32 + 32].copy_from_slice(&h);
        }
        len /= 2;
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&level[..32]);
    Some(root)
}

/// A content-addressed chunk's address: keccak256(span ‖ BMT root).
pub fn address_of(span: &[u8; SPAN_SIZE], payload: &[u8]) -> Option<[u8; 32]> {
    let root = bmt_root_of(payload)?;
    let mut data = [0u8; SPAN_SIZE + 32];
    data[..SPAN_SIZE].copy_from_slice(span);
    data[SPAN_SIZE..].copy_from_slice(&root);
    Some(keccak256(&data))
}

fn as_chunk(wire: &[u8]) -> Option<Chunk<'_>> {
    if wire.len() < SPAN_SIZE || wire.len() > MAX_CHUNK_WIRE {
        return None;
    }
    let mut span = [0u8; SPAN_SIZE];
    span.copy_from_slice(&wire[..SPAN_SIZE]);
    Some(Chunk {
        span,
        payload: &wire[SPAN_SIZE..],
    })
}

/// Ant's `cac_valid`: the wire is a span and at most 4096 bytes, and its
/// address is `address`. Neither node compares the span with the payload's
/// length, and trailing zeros don't change the address.
pub fn content_addressed<'a>(address: &[u8; 32], wire: &'a [u8]) -> Option<Chunk<'a>> {
    let chunk = as_chunk(wire)?;
    (address_of(&chunk.span, chunk.payload)? == *address).then_some(chunk)
}

/// A single-owner chunk that passed its check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingleOwner<'a> {
    pub id: [u8; 32],
    pub owner: [u8; 20],
    /// The wrapped chunk.
    pub chunk: Chunk<'a>,
    /// The wrapped chunk's address.
    pub chunk_address: [u8; 32],
}

/// `keccak256(id ‖ owner)`, a single-owner chunk's address.
pub fn soc_address(id: &[u8; 32], owner: &[u8; 20]) -> [u8; 32] {
    let mut data = [0u8; 52];
    data[..32].copy_from_slice(id);
    data[32..].copy_from_slice(owner);
    keccak256(&data)
}

/// Ant's `soc_valid`: `id ‖ signature ‖ span ‖ payload`, the signature over
/// the EIP-191 digest of `keccak256(id ‖ wrapped address)` recovering an
/// owner (fc_evm::recover_address's rules), the replicas owner only with
/// its identifier past the first byte equal to the wrapped address, and
/// `keccak256(id ‖ owner)` equal to `address`.
pub fn single_owner<'a>(address: &[u8; 32], wire: &'a [u8]) -> Option<SingleOwner<'a>> {
    if wire.len() < SOC_HEADER + SPAN_SIZE {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&wire[..SOC_ID]);
    let mut signature = [0u8; SOC_SIGNATURE];
    signature.copy_from_slice(&wire[SOC_ID..SOC_HEADER]);
    let chunk = as_chunk(&wire[SOC_HEADER..])?;
    let chunk_address = address_of(&chunk.span, chunk.payload)?;
    let mut signed = [0u8; 64];
    signed[..32].copy_from_slice(&id);
    signed[32..].copy_from_slice(&chunk_address);
    let owner = recover_address(&eip191_digest(&keccak256(&signed)), &signature).ok()?;
    if owner == REPLICAS_OWNER && id[1..] != chunk_address[1..] {
        return None;
    }
    (soc_address(&id, &owner) == *address).then_some(SingleOwner {
        id,
        owner,
        chunk,
        chunk_address,
    })
}

/// A piece the walk needs as a content-addressed chunk: a root, a manifest
/// node, an intermediate chunk, or a leaf's fallback. A valid single-owner
/// chunk at the address is unverifiable (deviation `soc-references`):
/// its owner could sign other content at the same address.
pub fn check_chunk<'a>(address: &[u8; 32], wire: &'a [u8]) -> Result<Chunk<'a>, Refusal> {
    if let Some(chunk) = content_addressed(address, wire) {
        return Ok(chunk);
    }
    if single_owner(address, wire).is_some() {
        return Err(Refusal::Unverifiable);
    }
    Err(Refusal::VerificationFailed)
}

/// What a feed update names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedUpdate {
    /// It wraps 40 bytes, `u64_be(timestamp) ‖ reference`.
    V1 { timestamp: u64, reference: [u8; 32] },
    /// It wraps the content's root chunk itself.
    V2 {
        root: [u8; 32],
        span: [u8; SPAN_SIZE],
        payload_len: usize,
    },
}

/// The feed update's identifier: `keccak256(topic ‖ u64_be(index))`.
pub fn feed_update_id(topic: &[u8; 32], index: u64) -> [u8; 32] {
    let mut data = [0u8; 40];
    data[..32].copy_from_slice(topic);
    data[32..].copy_from_slice(&index.to_be_bytes());
    keccak256(&data)
}

/// The feed update's address, which the walk computes and asks for.
pub fn feed_update_address(owner: &[u8; 20], topic: &[u8; 32], index: u64) -> [u8; 32] {
    soc_address(&feed_update_id(topic, index), owner)
}

/// A feed's update at `index`, served at the address the walk computed:
/// a single-owner chunk of the feed's owner and the index's identifier.
/// Ant reads a wrapped chunk of v1's length (48 bytes) as v1, one of 80 as
/// an encrypted v1 (unverifiable here: its reference is 64 bytes), and any
/// other as v2.
pub fn check_feed_update(
    owner: &[u8; 20],
    topic: &[u8; 32],
    index: u64,
    wire: &[u8],
) -> Result<FeedUpdate, Refusal> {
    let id = feed_update_id(topic, index);
    let soc = single_owner(&soc_address(&id, owner), wire).ok_or(Refusal::VerificationFailed)?;
    if soc.owner != *owner || soc.id != id {
        return Err(Refusal::VerificationFailed);
    }
    match soc.chunk.payload.len() {
        40 => {
            let mut ts = [0u8; 8];
            ts.copy_from_slice(&soc.chunk.payload[..8]);
            let mut reference = [0u8; 32];
            reference.copy_from_slice(&soc.chunk.payload[8..]);
            Ok(FeedUpdate::V1 {
                timestamp: u64::from_be_bytes(ts),
                reference,
            })
        }
        72 => Err(Refusal::Unverifiable),
        len => Ok(FeedUpdate::V2 {
            root: soc.chunk_address,
            span: soc.chunk.span,
            payload_len: len,
        }),
    }
}

/// Whether a leaf's streamed bytes, with the logical length its parent
/// gives it as span, hash to the address the parent names. When they
/// don't, the walk fetches the leaf from /chunks once ([`check_leaf_chunk`]).
pub fn leaf_matches(address: &[u8; 32], logical_len: usize, streamed: &[u8]) -> bool {
    streamed.len() == logical_len
        && address_of(&(logical_len as u64).to_le_bytes(), streamed) == Some(*address)
}

/// A leaf whose streamed bytes didn't match, checked against the chunk
/// /chunks answered: it must be a content-addressed chunk at the address
/// whose payload holds at least the logical length, and whose first
/// `logical_len` bytes are the streamed ones, which Ant serves whatever the
/// leaf's own span. A shorter payload is unverifiable.
pub fn check_leaf_chunk(
    address: &[u8; 32],
    logical_len: usize,
    streamed: &[u8],
    wire: &[u8],
) -> Result<(), Refusal> {
    let chunk = check_chunk(address, wire)?;
    if chunk.payload.len() < logical_len {
        return Err(Refusal::Unverifiable);
    }
    if streamed.len() != logical_len || chunk.payload[..logical_len] != *streamed {
        return Err(Refusal::VerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_empty_chunk_is_an_empty_files_reference() {
        let address = address_of(&[0; 8], &[]).unwrap();
        assert_eq!(
            fc_evm::to_hex(&address),
            "0xb34ca8c22b9e982354f9c7f50b470d66db428d880c8a904d5fe4ec9713171526"
        );
        assert!(check_chunk(&address, &[0; 8]).is_ok());
    }

    #[test]
    fn matches_the_signing_bmt() {
        let payload = [7u8; 1000];
        assert_eq!(bmt_root_of(&payload), crate::bmt_root(&payload).ok());
    }

    #[test]
    fn a_payload_past_4096_has_no_address() {
        assert_eq!(bmt_root_of(&[0; 4097]), None);
        assert!(as_chunk(&[0; MAX_CHUNK_WIRE + 1]).is_none());
    }
}
