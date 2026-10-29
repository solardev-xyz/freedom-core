//! A file's chunk tree as Ant v0.5.71's joiner reads it (design 0009,
//! Files): intermediate chunks, their erasure coding, and each child's
//! logical length, taken from the parent's geometry, never from the
//! child's own span.

use crate::CHUNK_SIZE;
use crate::verify::{Chunk, Refusal, SPAN_SIZE};

/// The most references an intermediate chunk holds.
pub const MAX_REFS: usize = 128;
const REF: usize = 32;

/// Bee's parity tables (`pkg/file/redundancy/level.go`, which Ant's
/// `rs.rs` copies): `(at least this many data shards, parities)`.
const MEDIUM: &[(usize, usize)] = &[
    (95, 9),
    (69, 8),
    (47, 7),
    (29, 6),
    (15, 5),
    (6, 4),
    (2, 3),
    (1, 2),
];
const STRONG: &[(usize, usize)] = &[
    (105, 21),
    (96, 20),
    (87, 19),
    (78, 18),
    (70, 17),
    (62, 16),
    (54, 15),
    (47, 14),
    (40, 13),
    (33, 12),
    (27, 11),
    (21, 10),
    (16, 9),
    (11, 8),
    (7, 7),
    (4, 6),
    (2, 5),
    (1, 4),
];
const INSANE: &[(usize, usize)] = &[
    (93, 31),
    (88, 30),
    (83, 29),
    (78, 28),
    (74, 27),
    (69, 26),
    (64, 25),
    (60, 24),
    (55, 23),
    (51, 22),
    (46, 21),
    (42, 20),
    (38, 19),
    (34, 18),
    (30, 17),
    (27, 16),
    (23, 15),
    (20, 14),
    (17, 13),
    (14, 12),
    (11, 11),
    (9, 10),
    (6, 9),
    (4, 8),
    (3, 7),
    (2, 6),
    (1, 5),
];
const PARANOID: &[(usize, usize)] = &[
    (37, 89),
    (36, 87),
    (35, 86),
    (34, 84),
    (33, 83),
    (32, 81),
    (31, 80),
    (30, 78),
    (29, 76),
    (28, 75),
    (27, 73),
    (26, 71),
    (25, 70),
    (24, 68),
    (23, 66),
    (22, 65),
    (21, 63),
    (20, 61),
    (19, 59),
    (18, 58),
    (17, 56),
    (16, 54),
    (15, 52),
    (14, 50),
    (13, 48),
    (12, 47),
    (11, 45),
    (10, 43),
    (9, 40),
    (8, 38),
    (7, 36),
    (6, 34),
    (5, 31),
    (4, 29),
    (3, 26),
    (2, 23),
    (1, 19),
];

/// Parities for `shards` data shards at `level` (Bee `GetParities`).
pub fn parities(level: u8, shards: usize) -> usize {
    let table = match level {
        1 => MEDIUM,
        2 => STRONG,
        3 => INSANE,
        4 => PARANOID,
        _ => return 0,
    };
    table
        .iter()
        .find(|&&(min, _)| shards >= min)
        .map_or(0, |&(_, p)| p)
}

/// The most data references a full intermediate chunk holds at `level`:
/// 128, 119, 107, 97 or 39 (Bee `GetMaxShards`).
pub fn max_shards(level: u8) -> usize {
    MAX_REFS - parities(level, MAX_REFS)
}

/// A span's redundancy level and its value without it (Bee `DecodeSpan`:
/// a top byte past 128 carries the level).
pub fn decode_span(span: &[u8; SPAN_SIZE]) -> (u8, u64) {
    let mut plain = *span;
    if plain[SPAN_SIZE - 1] > 128 {
        let level = plain[SPAN_SIZE - 1] & 0x7f;
        plain[SPAN_SIZE - 1] = 0;
        return (level, u64::from_le_bytes(plain));
    }
    (0, u64::from_le_bytes(plain))
}

/// The data shards a node of `span` bytes holds at a branching of
/// `branching` (Bee `ReferenceCount`, saturating as Ant does).
fn data_shards(span: u64, branching: u64) -> usize {
    let mut branch_size = CHUNK_SIZE as u64;
    let mut branch_level: u32 = 1;
    while branch_size < span {
        branch_size = branch_size.saturating_mul(branching);
        branch_level += 1;
    }
    let mut reference_size = CHUNK_SIZE as u64;
    let mut i = 1;
    while i + 1 < branch_level {
        reference_size = reference_size.saturating_mul(branching);
        i += 1;
    }
    let mut shards = 1usize;
    let mut offset = reference_size;
    while offset < span {
        offset = offset.saturating_add(reference_size);
        shards += 1;
    }
    shards
}

/// A chunk's own parity count, from its own span (Ant `chunk_meta`).
fn own_parities(span: &[u8; SPAN_SIZE]) -> usize {
    let (level, value) = decode_span(span);
    if level == 0 || value <= CHUNK_SIZE as u64 {
        return 0;
    }
    parities(level, data_shards(value, max_shards(level) as u64))
}

/// Each data child's capacity but the last's (Bee `subtrieSection`).
fn branch_size(refs: usize, span: u64, branching: u64) -> u64 {
    let refs = refs as u64;
    let mut branch = CHUNK_SIZE as u64;
    loop {
        if span.saturating_sub(branch.saturating_mul(refs.saturating_sub(1))) <= branch {
            return branch;
        }
        if branch > u64::MAX / branching {
            return branch;
        }
        branch *= branching;
    }
}

/// An intermediate chunk read as Ant's joiner reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intermediate<'a> {
    refs: &'a [u8],
    shards: usize,
    branch: u64,
    span: u64,
    /// The chunk's redundancy level, from its own span.
    pub level: u8,
    /// Its parity references, which the walk never reads.
    pub parities: usize,
}

impl<'a> Intermediate<'a> {
    /// The data children, in order.
    pub fn len(&self) -> usize {
        self.shards
    }

    pub fn is_empty(&self) -> bool {
        self.shards == 0
    }

    /// Child `i`: its address and logical length. The first children each
    /// cover a full branch; the last, the rest.
    pub fn child(&self, i: usize) -> Option<([u8; 32], u64)> {
        if i >= self.shards {
            return None;
        }
        let mut address = [0u8; 32];
        address.copy_from_slice(&self.refs[i * REF..i * REF + REF]);
        let before = self.branch.saturating_mul(i as u64);
        let length = if i + 1 == self.shards {
            self.span.saturating_sub(before)
        } else {
            self.branch.min(self.span.saturating_sub(before))
        };
        Some((address, length))
    }
}

/// Whether a node of `logical_len` bytes is a leaf, as the range joiner
/// reads it: one chunk's worth of bytes or fewer.
pub fn is_leaf(logical_len: u64) -> bool {
    logical_len <= CHUNK_SIZE as u64
}

/// Reads a chunk the walk holds as an intermediate node of `logical_len`
/// bytes (the root's own decoded span, or what its parent gives it).
/// Ant refuses, and so does the core (as unverifiable, the content being
/// authentic): a payload not made of whole references, one with no
/// non-zero reference after the trailing zeros Bee pads with, more than
/// 128 references, or at least as many parities as references.
pub fn intermediate<'a>(chunk: &Chunk<'a>, logical_len: u64) -> Result<Intermediate<'a>, Refusal> {
    let payload = chunk.payload;
    if !payload.len().is_multiple_of(REF) {
        return Err(Refusal::Unverifiable);
    }
    let mut effective = payload.len();
    while effective >= REF && payload[effective - REF..effective].iter().all(|&b| b == 0) {
        effective -= REF;
    }
    let refs = effective / REF;
    if refs == 0 || refs > MAX_REFS {
        return Err(Refusal::Unverifiable);
    }
    let (level, _) = decode_span(&chunk.span);
    let parities = own_parities(&chunk.span);
    if parities >= refs {
        return Err(Refusal::Unverifiable);
    }
    let shards = refs - parities;
    let branching = if level == 0 {
        MAX_REFS
    } else {
        max_shards(level)
    } as u64;
    Ok(Intermediate {
        refs: &payload[..effective],
        shards,
        branch: branch_size(shards, logical_len, branching),
        span: logical_len,
        level,
        parities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_shards_per_level() {
        assert_eq!([0, 1, 2, 3, 4].map(max_shards), [128, 119, 107, 97, 39]);
    }

    #[test]
    fn a_level_byte_is_decoded() {
        let mut span = 8192u64.to_le_bytes();
        span[7] = 0x81;
        assert_eq!(decode_span(&span), (1, 8192));
        // A top byte of 128 or less is a plain (huge) span.
        span[7] = 0x80;
        assert_eq!(decode_span(&span).0, 0);
    }
}
