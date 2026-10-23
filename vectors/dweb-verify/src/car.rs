//! CAR v1 and dag-pb, as far as the generator reads them: to take Kubo's
//! blocks out of `ipfs dag export`, to list the blocks of the CARs Kubo's
//! gateway sends, and to find each file's leaves.

use cid::Cid;
use std::io::Cursor;

fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut out: u64 = 0;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*pos)?;
        *pos += 1;
        out |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(out);
        }
    }
    None
}

/// A CAR v1's blocks, in order, after its header. `None` when the bytes
/// aren't a CAR the generator can read; a trailing partial section is
/// reported by `complete: false`.
pub struct Car {
    pub blocks: Vec<(Cid, Vec<u8>)>,
    pub complete: bool,
}

pub fn read(bytes: &[u8]) -> Option<Car> {
    let mut pos = 0usize;
    let header_len = usize::try_from(varint(bytes, &mut pos)?).ok()?;
    pos = pos.checked_add(header_len)?;
    if pos > bytes.len() {
        return None;
    }
    let mut blocks = Vec::new();
    while pos < bytes.len() {
        let start = pos;
        let Some(len) = varint(bytes, &mut pos).and_then(|l| usize::try_from(l).ok()) else {
            return Some(Car {
                blocks,
                complete: false,
            });
        };
        let Some(end) = pos.checked_add(len).filter(|&e| e <= bytes.len()) else {
            let _ = start;
            return Some(Car {
                blocks,
                complete: false,
            });
        };
        let section = &bytes[pos..end];
        let mut cur = Cursor::new(section);
        let Ok(cid) = Cid::read_bytes(&mut cur) else {
            return Some(Car {
                blocks,
                complete: false,
            });
        };
        let at = usize::try_from(cur.position()).ok()?;
        blocks.push((cid, section[at..].to_vec()));
        pos = end;
    }
    Some(Car {
        blocks,
        complete: true,
    })
}

/// A protobuf field: number, wire type, and its bytes' range for type 2.
fn fields(buf: &[u8]) -> Option<Vec<(u64, u8, usize, usize)>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let key = varint(buf, &mut pos)?;
        let (num, wt) = (key >> 3, u8::try_from(key & 7).ok()?);
        match wt {
            0 => {
                let start = pos;
                varint(buf, &mut pos)?;
                out.push((num, wt, start, pos));
            }
            2 => {
                let len = usize::try_from(varint(buf, &mut pos)?).ok()?;
                let end = pos.checked_add(len).filter(|&e| e <= buf.len())?;
                out.push((num, wt, pos, end));
                pos = end;
            }
            1 => pos = pos.checked_add(8)?,
            5 => pos = pos.checked_add(4)?,
            _ => return None,
        }
    }
    Some(out)
}

/// A dag-pb node: its links' CIDs in order, and the range of the UnixFS
/// `Data` bytes inside the block (the file bytes a leaf holds), if any.
pub struct PbNode {
    pub links: Vec<(Cid, String)>,
    pub unixfs_data: Option<(usize, usize)>,
}

pub fn dag_pb(block: &[u8]) -> Option<PbNode> {
    let mut links = Vec::new();
    let mut unixfs_data = None;
    for (num, wt, start, end) in fields(block)? {
        if wt != 2 {
            continue;
        }
        let body = &block[start..end];
        match num {
            2 => {
                let mut hash = None;
                let mut name = String::new();
                for (n, w, s, e) in fields(body)? {
                    if w == 2 && n == 1 {
                        hash = Cid::read_bytes(&mut Cursor::new(&body[s..e])).ok();
                    }
                    if w == 2 && n == 2 {
                        name = String::from_utf8_lossy(&body[s..e]).into_owned();
                    }
                }
                links.push((hash?, name));
            }
            1 => {
                for (n, w, s, e) in fields(body)? {
                    if w == 2 && n == 2 {
                        unixfs_data = Some((start + s, start + e));
                    }
                }
            }
            _ => {}
        }
    }
    Some(PbNode { links, unixfs_data })
}
