//! The write side's chunk tree (design 0015, Uploads, "Building the body"):
//! bytes in, Swarm's content-addressed chunks out, as `@ethersphere/core-sdk`
//! 0.2.2's `ChunkSplitter` and Bee's hashtrie build them. No encryption and
//! no erasure coding.
//!
//! - **Leaves** are the data's consecutive 4,096-byte slices; only the last
//!   may be shorter. Empty data is one empty leaf.
//! - **Intermediate chunks** hold up to 128 references, and each one's span
//!   is the length of the data below it.
//! - **The right edge:** where a level ends with a single leftover chunk, it
//!   isn't wrapped in an intermediate chunk of one reference: it is carried
//!   up unwrapped and referenced from the first level with room, as Bee's
//!   hashtrie `Sum` and core-sdk's `finalize` do. Ant v0.5.71's level-0
//!   splitter wraps it, which design 0009 records as `ant-lone-reference`;
//!   this follows Bee and bee-js.
//!
//! The tree this builds is the one [`crate::tree`] reads: every child but
//! the last covers a full branch, and a child of at most 4,096 bytes is a
//! leaf.
//!
//! **State:** the open leaf (4 KiB) and one open chunk of up to 128
//! references per level, at most eight levels below 2^64 bytes: under
//! 40 KiB however much data passes, and nothing else is kept. A chunk is
//! handed to the caller's sink as it is sealed, with its address, and only
//! the root is returned by [`Chunker::finish`].

use fc_evm::keccak256;

use crate::CHUNK_SIZE;
use crate::tree::MAX_REFS;
use crate::verify::{SPAN_SIZE, bmt_in_place};

const REF: usize = 32;

/// The chunker refuses only data past what a span can count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TreeError {
    #[error("data past 2^64 - 1 bytes")]
    TooLong,
}

/// A chunk the chunker sealed, as the node stores it: `span ‖ payload`, the
/// payload unpadded (a leaf's bytes, or an intermediate chunk's
/// references).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed<'a> {
    pub address: [u8; 32],
    pub span: u64,
    pub payload: &'a [u8],
}

/// The tree's root chunk: the reference a `/bytes` upload of the same data
/// answers, and the chunk a feed update over one chunk wraps
/// ([`crate::feed::Update::wrap`]). Only the chunker makes one, so its span
/// is always the number of bytes written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    address: [u8; 32],
    span: u64,
    payload: Vec<u8>,
}

impl Root {
    /// The tree's reference.
    pub fn address(&self) -> [u8; 32] {
        self.address
    }

    /// The data's length.
    pub fn span(&self) -> u64 {
        self.span
    }

    /// The root chunk's payload: the data itself for at most 4,096 bytes,
    /// otherwise its references.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// `span (8 bytes, little-endian) ‖ payload`, the chunk as `/chunks`
    /// serves it.
    pub fn wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SPAN_SIZE + self.payload.len());
        out.extend_from_slice(&self.span.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// An open intermediate chunk: its references so far and the span below
/// them.
#[derive(Debug, Clone, Default)]
struct Level {
    refs: Vec<u8>,
    span: u64,
}

impl Level {
    fn is_full(&self) -> bool {
        self.refs.len() == MAX_REFS * REF
    }

    fn append(&mut self, address: &[u8; 32], span: u64) {
        self.refs.extend_from_slice(address);
        self.span = self.span.saturating_add(span);
    }
}

/// A content-addressed chunk's address, `keccak256(span ‖ BMT(payload))`,
/// for a payload the chunker holds (at most 4,096 bytes by construction).
fn address(span: u64, payload: &[u8]) -> [u8; 32] {
    let mut level = [0u8; CHUNK_SIZE];
    let len = payload.len().min(CHUNK_SIZE);
    level[..len].copy_from_slice(&payload[..len]);
    let mut input = [0u8; SPAN_SIZE + 32];
    input[..SPAN_SIZE].copy_from_slice(&span.to_le_bytes());
    input[SPAN_SIZE..].copy_from_slice(&bmt_in_place(&mut level));
    keccak256(&input)
}

/// The streaming chunker. Feed it bytes in pieces of any size with
/// [`Chunker::write`]; each chunk is sealed as soon as the tree's shape
/// fixes it, and [`Chunker::finish`] seals the right edge and returns the
/// root.
#[derive(Debug, Clone)]
pub struct Chunker {
    leaf: Vec<u8>,
    /// `levels[k]` is the open chunk whose references are to chunks `k`
    /// levels above the leaves.
    levels: Vec<Level>,
    written: u64,
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new()
    }
}

impl Chunker {
    pub fn new() -> Self {
        Self {
            leaf: Vec::with_capacity(CHUNK_SIZE),
            levels: Vec::new(),
            written: 0,
        }
    }

    /// The bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Adds `data`, handing `sink` every chunk this seals. A leaf is sealed
    /// only once the byte after it arrives, as core-sdk seals it, so the
    /// last leaf stays open for [`Chunker::finish`]. Past 2^64 - 1 bytes in
    /// all, nothing of `data` is taken.
    pub fn write<F>(&mut self, mut data: &[u8], sink: &mut F) -> Result<(), TreeError>
    where
        F: FnMut(Sealed<'_>),
    {
        self.written = self
            .written
            .checked_add(data.len() as u64)
            .ok_or(TreeError::TooLong)?;
        while !data.is_empty() {
            if self.leaf.len() == CHUNK_SIZE {
                let (leaf, span) = self.seal_leaf(sink);
                self.push(0, &leaf, span, sink);
            }
            let take = (CHUNK_SIZE - self.leaf.len()).min(data.len());
            self.leaf.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(())
    }

    /// Seals the right edge and returns the root, which `sink` isn't
    /// handed: with the chunks `sink` saw, it is the whole tree.
    pub fn finish<F>(mut self, sink: &mut F) -> Root
    where
        F: FnMut(Sealed<'_>),
    {
        if self.levels.is_empty() {
            let span = self.leaf.len() as u64;
            return Root {
                address: address(span, &self.leaf),
                span,
                payload: self.leaf,
            };
        }
        // There are levels, so a byte followed a full leaf: the open leaf
        // isn't empty.
        let (mut node, mut node_span) = self.seal_leaf(sink);
        let mut k = 0;
        loop {
            if self.levels[k].is_full() {
                // No room for the leftover node here: this level's chunk is
                // sealed into the next, and the node is carried up
                // unwrapped.
                let (sealed, span) = self.seal_level(k, sink);
                self.push(k + 1, &sealed, span, sink);
                k += 1;
                continue;
            }
            self.levels[k].append(&node, node_span);
            if k + 1 == self.levels.len() {
                let level = std::mem::take(&mut self.levels[k]);
                return Root {
                    address: address(level.span, &level.refs),
                    span: level.span,
                    payload: level.refs,
                };
            }
            (node, node_span) = self.seal_level(k, sink);
            k += 1;
        }
    }

    fn seal_leaf<F>(&mut self, sink: &mut F) -> ([u8; 32], u64)
    where
        F: FnMut(Sealed<'_>),
    {
        let span = self.leaf.len() as u64;
        let address = address(span, &self.leaf);
        sink(Sealed {
            address,
            span,
            payload: &self.leaf,
        });
        self.leaf.clear();
        (address, span)
    }

    fn seal_level<F>(&mut self, k: usize, sink: &mut F) -> ([u8; 32], u64)
    where
        F: FnMut(Sealed<'_>),
    {
        let level = &mut self.levels[k];
        let span = level.span;
        let address = address(span, &level.refs);
        sink(Sealed {
            address,
            span,
            payload: &level.refs,
        });
        level.refs.clear();
        level.span = 0;
        (address, span)
    }

    /// Adds a sealed chunk's reference to level `k`, sealing that level's
    /// chunk into the next first when it already holds 128.
    fn push<F>(&mut self, k: usize, address: &[u8; 32], span: u64, sink: &mut F)
    where
        F: FnMut(Sealed<'_>),
    {
        if k == self.levels.len() {
            self.levels.push(Level {
                refs: Vec::with_capacity(MAX_REFS * REF),
                span: 0,
            });
        }
        if self.levels[k].is_full() {
            let (sealed, sealed_span) = self.seal_level(k, sink);
            self.push(k + 1, &sealed, sealed_span, sink);
        }
        self.levels[k].append(address, span);
    }
}

/// The root of `data`'s tree, its other chunks dropped: a chunk's address
/// for `publishChunk`, or a tree's reference.
pub fn root_of(data: &[u8]) -> Result<Root, TreeError> {
    let mut chunker = Chunker::new();
    chunker.write(data, &mut |_| {})?;
    Ok(chunker.finish(&mut |_| {}))
}

/// How many references the root of a tree over `span` bytes holds: 0 for a
/// leaf root (at most 4,096 bytes), otherwise the number of full branches
/// it takes, the last one partial. A wrapped root chunk is held to it
/// ([`crate::feed::Update::wrap`]).
pub fn root_refs(span: u64) -> usize {
    if span <= CHUNK_SIZE as u64 {
        return 0;
    }
    let mut branch = CHUNK_SIZE as u64;
    while span.div_ceil(branch) > MAX_REFS as u64 {
        branch = branch.saturating_mul(MAX_REFS as u64);
    }
    span.div_ceil(branch) as usize
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn empty_data_is_the_empty_chunk() {
        let root = root_of(&[]).unwrap();
        assert_eq!(
            hex(&root.address()),
            "b34ca8c22b9e982354f9c7f50b470d66db428d880c8a904d5fe4ec9713171526"
        );
        assert_eq!(root.wire(), vec![0u8; 8]);
    }

    #[test]
    fn root_refs_per_span() {
        assert_eq!(root_refs(0), 0);
        assert_eq!(root_refs(4096), 0);
        assert_eq!(root_refs(4097), 2);
        assert_eq!(root_refs(128 * 4096), 128);
        assert_eq!(root_refs(128 * 4096 + 1), 2);
        assert_eq!(root_refs(128 * 128 * 4096 + 1), 2);
        assert_eq!(root_refs(u64::MAX), 8);
    }

    #[test]
    fn a_span_past_u64_is_refused_and_nothing_taken() {
        let mut chunker = Chunker::new();
        chunker.written = u64::MAX - 1;
        assert_eq!(chunker.write(&[1, 2], &mut |_| {}), Err(TreeError::TooLong));
        assert_eq!(chunker.written(), u64::MAX - 1);
        assert!(chunker.leaf.is_empty());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
