//! dag-pb nodes (the DAG-PB specification; IPIP-0550 for field order),
//! read in two passes over a block that passed its CID: the first checks
//! the structure and counts the links, allocating nothing; the second, an
//! iterator, yields views.

use crate::Refusal;
use crate::cid::{self, Cid};
use crate::pb::{self, Value};

/// The most links a node may hold (deviation `decoder-caps`): a
/// supported-content limit, not a malformedness test.
pub const MAX_LINKS: usize = 65_536;

/// A node that passed the first pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node<'a> {
    message: &'a [u8],
    /// The `Data` field (the last one, as protobuf reads repeats).
    pub data: Option<&'a [u8]>,
    pub link_count: usize,
}

/// A link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link<'a> {
    pub cid: Cid<'a>,
    pub name: Option<&'a str>,
    pub tsize: Option<u64>,
}

fn link(bytes: &[u8]) -> Result<Link<'_>, Refusal> {
    let mut hash = None;
    let mut name = None;
    let mut tsize = None;
    for field in pb::fields(bytes) {
        match field.map_err(|()| Refusal::Malformed)? {
            (1, Value::Bytes(h)) => hash = Some(h),
            (2, Value::Bytes(n)) => {
                name = Some(std::str::from_utf8(n).map_err(|_| Refusal::Malformed)?);
            }
            (3, Value::Varint(t)) => tsize = Some(t),
            (1..=3, _) => return Err(Refusal::Malformed),
            _ => {}
        }
    }
    let hash = hash.ok_or(Refusal::Malformed)?;
    let cid = cid::parse(hash).ok_or(Refusal::Malformed)?;
    Ok(Link { cid, name, tsize })
}

/// The first pass. A link without a hash, a hash that isn't a CID, a
/// name that isn't UTF-8, a known field of the wrong wire type, a group,
/// an over-long varint or a length past the end is malformed; more than
/// [`MAX_LINKS`] links is unverifiable, and is found by counting before
/// any link is read.
pub fn decode(block: &[u8]) -> Result<Node<'_>, Refusal> {
    let mut data = None;
    let mut count = 0usize;
    for field in pb::fields(block) {
        match field.map_err(|()| Refusal::Malformed)? {
            (2, Value::Bytes(_)) => count += 1,
            (1, Value::Bytes(d)) => data = Some(d),
            (1 | 2, _) => return Err(Refusal::Malformed),
            _ => {}
        }
    }
    if count > MAX_LINKS {
        return Err(Refusal::Unverifiable);
    }
    for field in pb::fields(block) {
        if let Ok((2, Value::Bytes(l))) = field {
            link(l)?;
        }
    }
    Ok(Node {
        message: block,
        data,
        link_count: count,
    })
}

impl<'a> Node<'a> {
    /// The links, in order.
    pub fn links(&self) -> impl Iterator<Item = Link<'a>> + 'a {
        pb::fields(self.message).filter_map(|f| match f {
            Ok((2, Value::Bytes(l))) => link(l).ok(),
            _ => None,
        })
    }
}
