//! UnixFS `Data` (the UnixFS specification), and the stricter size rules
//! verified mode holds files to (deviation `unixfs-sizes`): one
//! `blocksizes` entry per link, and content that adds up to `filesize`.

use crate::Refusal;
use crate::dagpb::{MAX_LINKS, Node};
use crate::pb::{self, Value};
use crate::varint;

/// A node's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Raw,
    Directory,
    File,
    Metadata,
    Symlink,
    HamtShard,
}

/// murmur3-x64-64, the only HAMT hash the native node reads.
pub const MURMUR3: u64 = 0x22;
/// The only HAMT fanout the native node reads.
pub const FANOUT: u64 = 256;

/// A node's UnixFS `Data`, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data<'a> {
    pub kind: Kind,
    pub data: Option<&'a [u8]>,
    pub filesize: Option<u64>,
    blocksizes: &'a [u8],
    pub blocksize_count: usize,
}

impl<'a> Data<'a> {
    /// The `blocksizes` entries, packed or not.
    pub fn blocksizes(&self) -> impl Iterator<Item = u64> + 'a {
        pb::fields(self.blocksizes).flat_map(|f| {
            let packed = match f {
                Ok((4, Value::Bytes(p))) => p,
                _ => &[][..],
            };
            let single = match f {
                Ok((4, Value::Varint(v))) => Some(v),
                _ => None,
            };
            single.into_iter().chain(Packed(packed))
        })
    }
}

struct Packed<'a>(&'a [u8]);

impl Iterator for Packed<'_> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        let (v, n) = varint::read(self.0)?;
        self.0 = &self.0[n..];
        Some(v)
    }
}

fn count_packed(mut p: &[u8]) -> Option<usize> {
    let mut n = 0usize;
    while !p.is_empty() {
        let (_, used) = varint::read(p)?;
        p = &p[used..];
        n += 1;
    }
    Some(n)
}

/// Decodes a dag-pb node's `Data` as UnixFS and checks it against the
/// node's links:
/// - more `blocksizes` entries than [`MAX_LINKS`] is unverifiable, counted
///   before they're compared with the links;
/// - a file (or raw node) needs `filesize`, one entry per link, and
///   `filesize` equal to its `Data` plus the entries (malformed otherwise);
/// - a HAMT shard of another hash or fanout is unverifiable.
pub fn decode<'a>(node: &Node<'a>) -> Result<Data<'a>, Refusal> {
    let bytes = node.data.ok_or(Refusal::Malformed)?;
    let mut kind = None;
    let mut data = None;
    let mut filesize = None;
    let mut count = 0usize;
    let mut hash_type = None;
    let mut fanout = None;
    for field in pb::fields(bytes) {
        match field.map_err(|()| Refusal::Malformed)? {
            (1, Value::Varint(t)) => {
                kind = Some(match t {
                    0 => Kind::Raw,
                    1 => Kind::Directory,
                    2 => Kind::File,
                    3 => Kind::Metadata,
                    4 => Kind::Symlink,
                    5 => Kind::HamtShard,
                    _ => return Err(Refusal::Malformed),
                });
            }
            (2, Value::Bytes(d)) => data = Some(d),
            (3, Value::Varint(s)) => filesize = Some(s),
            (4, Value::Varint(_)) => count += 1,
            (4, Value::Bytes(p)) => count += count_packed(p).ok_or(Refusal::Malformed)?,
            (5, Value::Varint(h)) => hash_type = Some(h),
            (6, Value::Varint(f)) => fanout = Some(f),
            (1..=6, _) => return Err(Refusal::Malformed),
            _ => {}
        }
        if count > MAX_LINKS {
            return Err(Refusal::Unverifiable);
        }
    }
    let kind = kind.ok_or(Refusal::Malformed)?;
    let out = Data {
        kind,
        data,
        filesize,
        blocksizes: bytes,
        blocksize_count: count,
    };
    match kind {
        Kind::File | Kind::Raw => {
            if count != node.link_count {
                return Err(Refusal::Malformed);
            }
            let size = filesize.ok_or(Refusal::Malformed)?;
            let mut total = data.map_or(0, |d| d.len() as u64);
            for b in out.blocksizes() {
                total = total.checked_add(b).ok_or(Refusal::Malformed)?;
            }
            if total != size {
                return Err(Refusal::Malformed);
            }
        }
        Kind::HamtShard if hash_type != Some(MURMUR3) || fanout != Some(FANOUT) => {
            return Err(Refusal::Unverifiable);
        }
        _ => {}
    }
    Ok(out)
}
