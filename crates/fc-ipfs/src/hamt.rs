//! HAMT-sharded directories, looked up by hash as Kubo's gateway does
//! (boxo `hamt.go`): the first 64 bits of MurmurHash3 x64 128 of the name,
//! seed 0, big-endian, a byte per level; the shard's bitfield says whether
//! the bucket is occupied, and the link is the one at the bucket's position
//! among the set bits. The native reader finds an entry by name instead
//! (deviation `hamt-lookup`): an entry that isn't where its hash and the
//! bitfield point isn't found here.

use crate::dagpb::{Link, Node};
use crate::murmur3;

/// The most shard levels a lookup descends (0009, Bounds).
pub const MAX_LEVELS: usize = 8;

/// The bits a name's lookup consumes, a byte per level.
pub fn hash_bits(name: &str) -> [u8; 8] {
    murmur3::x64_128(name.as_bytes(), 0).0.to_be_bytes()
}

/// One shard's answer for a name at `level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step<'a> {
    /// The entry.
    Entry(Link<'a>),
    /// The sub-shard to read next, at `level + 1`.
    Shard(Link<'a>),
    /// Not in the directory.
    Absent,
}

fn hex2(b: u8) -> [u8; 2] {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    [H[usize::from(b >> 4)], H[usize::from(b & 15)]]
}

/// Looks `name` up in a shard whose UnixFS `Data` holds `bitfield` (a
/// big-endian integer, right-aligned).
pub fn step<'a>(shard: &Node<'a>, bitfield: &[u8], name: &str, level: usize) -> Step<'a> {
    let Some(&bucket) = hash_bits(name).get(level) else {
        return Step::Absent;
    };
    let set = |i: usize| -> bool {
        let byte = i / 8;
        byte < bitfield.len() && (bitfield[bitfield.len() - 1 - byte] >> (i % 8)) & 1 == 1
    };
    let bucket = usize::from(bucket);
    if !set(bucket) {
        return Step::Absent;
    }
    let position = (0..bucket).filter(|&i| set(i)).count();
    let Some(link) = shard.links().nth(position) else {
        return Step::Absent;
    };
    let label = link.name.unwrap_or("");
    let prefix = hex2(bucket as u8);
    if label.len() < 2 || label.as_bytes()[..2] != prefix {
        // Not where the hash points: absent here (hamt-lookup).
        return Step::Absent;
    }
    if label.len() == 2 {
        return Step::Shard(link);
    }
    if &label[2..] == name {
        Step::Entry(link)
    } else {
        Step::Absent
    }
}
