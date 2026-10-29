//! IPFS piece checks: blocks against their CIDs, dag-pb and UnixFS decoding
//! with the bounded decoders' caps, HAMT lookup by hash, and CAR framing
//! (0009, Blocks and DAGs, Bounded decoding, The CAR request).

use super::{Err, bytes, fail, ok, parts};
use crate::ipns::{pb_bytes, pb_varint};
use base64::Engine;
use cid::Cid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const DAG_PB: u64 = 0x70;
const RAW: u64 = 0x55;
const MAX_BLOCK: usize = 2 * 1024 * 1024;

fn mh(code: u64, digest: &[u8]) -> Result<multihash::Multihash<64>, Err> {
    Ok(multihash::Multihash::<64>::wrap(code, digest)?)
}

fn sha256_cid(codec: u64, block: &[u8]) -> Result<Cid, Err> {
    Ok(Cid::new_v1(codec, mh(0x12, &Sha256::digest(block))?))
}

fn v0(block: &[u8]) -> Result<Cid, Err> {
    Ok(Cid::new_v0(mh(0x12, &Sha256::digest(block))?)?)
}

fn identity_cid(data: &[u8]) -> Result<Cid, Err> {
    Ok(Cid::new_v1(RAW, mh(0x00, data)?))
}

/// Whether a CID's digest is its block's under the hash it names, for the
/// hashes the cases use; `None` for another.
fn honest_digest(cid: &Cid, block: &[u8]) -> Option<bool> {
    let d = cid.hash().digest();
    Some(match cid.hash().code() {
        0x00 => d == block,
        0x12 => d == Sha256::digest(block).as_slice(),
        0x13 => d == sha2::Sha512::digest(block).as_slice(),
        0x1e => d == blake3::hash(block).as_bytes(),
        _ => return None,
    })
}

fn native(cid: &Cid, block: &[u8]) -> Value {
    match freedom_ipfs_core::verify_block(cid, block) {
        Ok(()) => json!({ "verify_block": "ok" }),
        Err(e) => json!({ "verify_block": e.to_string() }),
    }
}

struct Link {
    hash: Option<Vec<u8>>,
    name: Option<String>,
    tsize: Option<u64>,
}

fn link(cid: &Cid, name: &str, tsize: u64) -> Link {
    Link {
        hash: Some(cid.to_bytes()),
        name: Some(name.to_string()),
        tsize: Some(tsize),
    }
}

fn pb_link(l: &Link) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(h) = &l.hash {
        pb_bytes(1, h, &mut out);
    }
    if let Some(n) = &l.name {
        pb_bytes(2, n.as_bytes(), &mut out);
    }
    if let Some(t) = l.tsize {
        pb_varint(3, t, &mut out);
    }
    out
}

/// A dag-pb node in its canonical form: the links, then `Data`.
fn pb_node(links: &[Link], data: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for l in links {
        pb_bytes(2, &pb_link(l), &mut out);
    }
    if let Some(d) = data {
        pb_bytes(1, d, &mut out);
    }
    out
}

struct Unixfs {
    kind: u64,
    data: Option<Vec<u8>>,
    filesize: Option<u64>,
    blocksizes: Vec<u64>,
    hash_type: Option<u64>,
    fanout: Option<u64>,
}

impl Unixfs {
    fn new(kind: u64) -> Self {
        Self {
            kind,
            data: None,
            filesize: None,
            blocksizes: Vec::new(),
            hash_type: None,
            fanout: None,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        pb_varint(1, self.kind, &mut out);
        if let Some(d) = &self.data {
            pb_bytes(2, d, &mut out);
        }
        if let Some(f) = self.filesize {
            pb_varint(3, f, &mut out);
        }
        for b in &self.blocksizes {
            pb_varint(4, *b, &mut out);
        }
        if let Some(h) = self.hash_type {
            pb_varint(5, h, &mut out);
        }
        if let Some(f) = self.fanout {
            pb_varint(6, f, &mut out);
        }
        out
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn blocks() -> Result<Vec<Value>, Err> {
    let mut out = Vec::new();
    let mut push = |id: &str,
                    note: &str,
                    cid: &Cid,
                    block: &[u8],
                    block_v: Value,
                    expect: Value|
     -> Result<(), Err> {
        // verify_block reads the hash and the size; a codec it doesn't serve
        // is the walk's refusal, the one way the two may differ here. Its
        // error must be the case's one change: an unsupported hash over
        // an honest digest, a size past the limit, or a mismatch.
        use freedom_ipfs_core::CoreError;
        let verdict = freedom_ipfs_core::verify_block(cid, block);
        let honest = honest_digest(cid, block);
        let fits = match (&verdict, expect.get("ok"), expect["fail"].as_str()) {
            (Ok(()), Some(_), _) => honest == Some(true),
            // Only dag-pb and raw are read: the hash checks.
            (Ok(()), None, Some("unverifiable")) => {
                cid.codec() != DAG_PB && cid.codec() != RAW && honest == Some(true)
            }
            (Err(CoreError::UnsupportedHash(_)), None, Some("unverifiable")) => {
                honest == Some(true)
            }
            (Err(CoreError::BlockTooLarge { .. }), None, Some("verification_failed")) => {
                honest == Some(true)
            }
            (Err(CoreError::HashMismatch { .. }), None, Some("verification_failed")) => {
                honest == Some(false)
            }
            _ => false,
        };
        if !fits {
            return Err(format!(
                "block case {id}: verify_block's {verdict:?} doesn't fit {expect}"
            )
            .into());
        }
        out.push(json!({
            "id": id,
            "note": note,
            "cid": cid.to_string(),
            "block": block_v,
            "expect": expect,
            "native": native(cid, block),
        }));
        Ok(())
    };
    let raw = crate::content::bytes("checks-block-raw", 1000);
    let c = sha256_cid(RAW, &raw)?;
    push(
        "raw",
        "a raw block and its CIDv1",
        &c,
        &raw,
        bytes(&raw),
        ok(json!({ "codec": "raw" })),
    )?;
    let mut flipped = raw.clone();
    flipped[500] ^= 0x01;
    push(
        "raw-flipped",
        "the raw block with byte 500 flipped",
        &c,
        &flipped,
        bytes(&flipped),
        fail("verification_failed"),
    )?;
    let mut leaf = Unixfs::new(2);
    leaf.data = Some(b"checks".to_vec());
    leaf.filesize = Some(6);
    let node = pb_node(&[], Some(&leaf.encode()));
    let c0 = v0(&node)?;
    push(
        "dag-pb-v0",
        "a dag-pb node and its CIDv0",
        &c0,
        &node,
        bytes(&node),
        ok(json!({ "codec": "dag-pb" })),
    )?;
    let c1 = sha256_cid(DAG_PB, &node)?;
    push(
        "dag-pb-v1",
        "the same node and its CIDv1: a link matches a block when codec and multihash agree",
        &c1,
        &node,
        bytes(&node),
        ok(json!({ "codec": "dag-pb" })),
    )?;
    let id = identity_cid(b"hello")?;
    push(
        "identity",
        "an identity CID: its block is its digest",
        &id,
        b"hello",
        bytes(b"hello"),
        ok(json!({ "codec": "raw" })),
    )?;
    push(
        "identity-mismatch",
        "an identity CID with other bytes",
        &id,
        b"hellp",
        bytes(b"hellp"),
        fail("verification_failed"),
    )?;
    let unit = [0x5a_u8; 32];
    let (max, max_v) = parts(&[(&[][..], &unit[..], MAX_BLOCK / 32)]);
    let cm = sha256_cid(RAW, &max)?;
    push(
        "2-mib",
        "a raw block of exactly 2 MiB",
        &cm,
        &max,
        max_v,
        ok(json!({ "codec": "raw" })),
    )?;
    let (over, over_v) = parts(&[
        (&[][..], &unit[..], MAX_BLOCK / 32),
        (&[0x5a_u8][..], &[][..], 0),
    ]);
    let co = sha256_cid(RAW, &over)?;
    push(
        "2-mib-plus-1",
        "a raw block of 2 MiB and one byte, its CID correct: past the block limit",
        &co,
        &over,
        over_v,
        fail("verification_failed"),
    )?;
    let blake3 = Cid::new_v1(RAW, mh(0x1e, blake3::hash(&raw).as_bytes())?);
    push(
        "blake3",
        "a blake3 CID with the block's BLAKE3 digest: an unsupported hash, honest",
        &blake3,
        &raw,
        bytes(&raw),
        fail("unverifiable"),
    )?;
    let sha512 = Cid::new_v1(RAW, mh(0x13, &sha2::Sha512::digest(&raw))?);
    push(
        "sha2-512",
        "a sha2-512 CID with the block's SHA-512 digest: an unsupported hash, honest",
        &sha512,
        &raw,
        bytes(&raw),
        fail("unverifiable"),
    )?;
    let truncated = Cid::new_v1(RAW, mh(0x12, &Sha256::digest(&raw)[..20])?);
    push(
        "sha2-256-short-digest",
        "a sha2-256 CID whose digest is the real one's first 20 bytes",
        &truncated,
        &raw,
        bytes(&raw),
        fail("verification_failed"),
    )?;
    let cbor = sha256_cid(0x71, &raw)?;
    push(
        "dag-cbor",
        "a dag-cbor CID whose hash matches: only dag-pb and raw are read",
        &cbor,
        &raw,
        bytes(&raw),
        fail("unverifiable"),
    )?;
    Ok(out)
}

fn link_json(l: &Link) -> Result<Value, Err> {
    let hash = match &l.hash {
        Some(h) => Value::String(Cid::try_from(h.as_slice())?.to_string()),
        None => Value::Null,
    };
    Ok(json!({ "hash": hash, "name": l.name, "tsize": l.tsize }))
}

fn decoded(links: &[Link], data: Option<&[u8]>) -> Result<Value, Err> {
    let mut v = json!({ "link_count": links.len(), "data": data.map(b64) });
    if links.len() <= 16 {
        v["links"] = Value::Array(links.iter().map(link_json).collect::<Result<_, _>>()?);
    }
    Ok(ok(v))
}

fn dag_pb() -> Result<Vec<Value>, Err> {
    let mut out = Vec::new();
    let mut push = |id: &str,
                    note: &str,
                    block: &[u8],
                    block_v: Value,
                    expect: Value,
                    deviation: Option<&str>|
     -> Result<(), Err> {
        let mut case = json!({
            "id": id,
            "note": note,
            "cid": sha256_cid(DAG_PB, block)?.to_string(),
            "block": block_v,
            "expect": expect,
        });
        if let Some(d) = deviation {
            case["deviation"] = json!(d);
        }
        out.push(case);
        Ok(())
    };
    let a = crate::content::bytes("checks-dag-a", 300);
    let b = crate::content::bytes("checks-dag-b", 200);
    let la = link(&sha256_cid(RAW, &a)?, "", 300);
    let lb = link(&sha256_cid(RAW, &b)?, "", 200);
    let mut file = Unixfs::new(2);
    file.filesize = Some(500);
    file.blocksizes = vec![300, 200];
    let fdata = file.encode();
    let links = [la, lb];
    let node = pb_node(&links, Some(&fdata));
    push(
        "file",
        "a file node over two raw leaves",
        &node,
        bytes(&node),
        decoded(&links, Some(&fdata))?,
        None,
    )?;
    let mut reversed = Vec::new();
    pb_bytes(1, &fdata, &mut reversed);
    for l in &links {
        pb_bytes(2, &pb_link(l), &mut reversed);
    }
    push(
        "data-first",
        "the same node with Data before Links: either order is read (IPIP-0550)",
        &reversed,
        bytes(&reversed),
        decoded(&links, Some(&fdata))?,
        None,
    )?;
    let named = [
        link(&sha256_cid(RAW, &a)?, "a.txt", 300),
        link(&v0(&node)?, "ünï.txt", 600),
    ];
    let dir = pb_node(&named, Some(&Unixfs::new(1).encode()));
    push(
        "directory",
        "a directory of two named links, one a CIDv0",
        &dir,
        bytes(&dir),
        decoded(&named, Some(&Unixfs::new(1).encode()))?,
        None,
    )?;
    let no_data = pb_node(&named, None);
    push(
        "no-data",
        "links and no Data field",
        &no_data,
        bytes(&no_data),
        decoded(&named, None)?,
        None,
    )?;
    let no_hash = [Link {
        hash: None,
        name: Some("x".into()),
        tsize: Some(1),
    }];
    let bad = pb_node(&no_hash, None);
    push(
        "link-without-hash",
        "a PBLink without Hash: refused in the first pass",
        &bad,
        bytes(&bad),
        fail("malformed"),
        None,
    )?;
    let mut unknown = node.clone();
    pb_varint(5, 7, &mut unknown);
    push(
        "unknown-field",
        "the file node with an unknown varint field: skipped",
        &unknown,
        bytes(&unknown),
        decoded(&links, Some(&fdata))?,
        None,
    )?;
    let mut group = node.clone();
    group.extend_from_slice(&[0x2b, 0x2c]);
    push(
        "group",
        "a start-group and end-group pair (field 5): groups are refused",
        &group,
        bytes(&group),
        fail("malformed"),
        None,
    )?;
    let mut long_varint = node.clone();
    long_varint.extend_from_slice(&[
        0x28, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    ]);
    push(
        "varint-11-bytes",
        "an unknown varint field whose value takes 11 bytes",
        &long_varint,
        bytes(&long_varint),
        fail("malformed"),
        None,
    )?;
    let mut past = node.clone();
    past.extend_from_slice(&[0x0a, 0x7f, 0x00]);
    push(
        "length-past-end",
        "a second Data field claiming 127 bytes where one remains",
        &past,
        bytes(&past),
        fail("malformed"),
        None,
    )?;
    // Links to the empty identity CID, nothing else: the smallest links.
    let empty = identity_cid(&[])?.to_bytes();
    let mut one = Vec::new();
    pb_bytes(1, &empty, &mut one);
    let mut field = Vec::new();
    pb_bytes(2, &one, &mut field);
    let (at_cap, at_cap_v) = parts(&[(&[][..], &field[..], 65_536)]);
    let cap_links: Vec<Link> = (0..65_536)
        .map(|_| Link {
            hash: Some(empty.clone()),
            name: None,
            tsize: None,
        })
        .collect();
    push(
        "links-65536",
        "65,536 links to the empty identity CID: at the cap",
        &at_cap,
        at_cap_v,
        decoded(&cap_links, None)?,
        None,
    )?;
    let (past_cap, past_cap_v) = parts(&[(&[][..], &field[..], 65_537)]);
    push(
        "links-65537",
        "65,537 links: past the cap, refused as unverifiable, not malformed",
        &past_cap,
        past_cap_v,
        fail("unverifiable"),
        Some("decoder-caps"),
    )?;
    let (max, max_v) = parts(&[(&[][..], &field[..], MAX_BLOCK / field.len())]);
    push(
        "links-maximal",
        "as many minimal links as 2 MiB holds (262,144): counted, not allocated, then refused",
        &max,
        max_v,
        fail("unverifiable"),
        Some("decoder-caps"),
    )?;
    let unit = [0x78u8, 0x00];
    let mut d = Vec::new();
    pb_bytes(1, &Unixfs::new(2).encode(), &mut d);
    let (unk, unk_v) = parts(&[
        (&[][..], &unit[..], (MAX_BLOCK - d.len()) / 2),
        (&d[..], &[][..], 0),
    ]);
    push(
        "unknown-maximal",
        "2 MiB of unknown varint fields (field 15), then Data: skipped in linear time, no memory",
        &unk,
        unk_v,
        decoded(&[], Some(&Unixfs::new(2).encode()))?,
        None,
    )?;
    Ok(out)
}

fn unixfs() -> Result<Vec<Value>, Err> {
    let mut out = Vec::new();
    let mut push = |id: &str,
                    note: &str,
                    node: &[u8],
                    node_v: Value,
                    expect: Value,
                    deviation: Option<&str>|
     -> Result<(), Err> {
        let mut case = json!({
            "id": id,
            "note": note,
            "cid": sha256_cid(DAG_PB, node)?.to_string(),
            "block": node_v,
            "expect": expect,
        });
        if let Some(d) = deviation {
            case["deviation"] = json!(d);
        }
        out.push(case);
        Ok(())
    };
    let summary = |u: &Unixfs, links: usize| {
        const TYPES: [&str; 6] = [
            "raw",
            "directory",
            "file",
            "metadata",
            "symlink",
            "hamt_shard",
        ];
        let kind = TYPES.get(u.kind as usize).copied().unwrap_or("unknown");
        json!({
            "type": kind,
            "filesize": u.filesize,
            "blocksizes": u.blocksizes,
            "data_length": u.data.as_ref().map_or(0, Vec::len),
            "links": links,
        })
    };
    let a = crate::content::bytes("checks-unixfs-a", 300);
    let b = crate::content::bytes("checks-unixfs-b", 200);
    let la = link(&sha256_cid(RAW, &a)?, "", 300);
    let lb = link(&sha256_cid(RAW, &b)?, "", 200);
    let mut inline = Unixfs::new(2);
    inline.data = Some(b"inline".to_vec());
    inline.filesize = Some(6);
    let n = pb_node(&[], Some(&inline.encode()));
    push(
        "file-inline",
        "a file whose content is its own Data",
        &n,
        bytes(&n),
        ok(summary(&inline, 0)),
        None,
    )?;
    let mut file = Unixfs::new(2);
    file.filesize = Some(500);
    file.blocksizes = vec![300, 200];
    let links = [la, lb];
    let n = pb_node(&links, Some(&file.encode()));
    push(
        "file",
        "a file over two leaves, its sizes consistent",
        &n,
        bytes(&n),
        ok(summary(&file, 2)),
        None,
    )?;
    let mut mixed = Unixfs::new(2);
    mixed.data = Some(b"head".to_vec());
    mixed.filesize = Some(504);
    mixed.blocksizes = vec![300, 200];
    let n = pb_node(&links, Some(&mixed.encode()));
    push(
        "file-data-and-links",
        "Data, then the links' content: filesize counts both",
        &n,
        bytes(&n),
        ok(summary(&mixed, 2)),
        None,
    )?;
    let mut fewer = Unixfs::new(2);
    fewer.filesize = Some(500);
    fewer.blocksizes = vec![500];
    let n = pb_node(&links, Some(&fewer.encode()));
    push(
        "blocksizes-fewer-than-links",
        "one blocksizes entry for two links",
        &n,
        bytes(&n),
        fail("malformed"),
        Some("unixfs-sizes"),
    )?;
    let mut sum = Unixfs::new(2);
    sum.filesize = Some(600);
    sum.blocksizes = vec![300, 200];
    let n = pb_node(&links, Some(&sum.encode()));
    push(
        "filesize-mismatch",
        "filesize 600 over content of 500",
        &n,
        bytes(&n),
        fail("malformed"),
        Some("unixfs-sizes"),
    )?;
    let mut dir = Unixfs::new(1);
    let n = pb_node(&[], Some(&dir.encode()));
    push(
        "directory",
        "an empty directory",
        &n,
        bytes(&n),
        ok(summary(&dir, 0)),
        None,
    )?;
    dir.kind = 5;
    dir.hash_type = Some(0x22);
    dir.fanout = Some(256);
    dir.data = Some(vec![0x00]);
    let n = pb_node(&[], Some(&dir.encode()));
    push(
        "hamt-shard",
        "a HAMT shard: murmur3-x64-64 (0x22), fanout 256, an empty bitfield",
        &n,
        bytes(&n),
        ok(summary(&dir, 0)),
        None,
    )?;
    let mut f16 = Unixfs::new(5);
    f16.hash_type = Some(0x22);
    f16.fanout = Some(16);
    f16.data = Some(vec![0x00]);
    let n = pb_node(&[], Some(&f16.encode()));
    push(
        "hamt-fanout-16",
        "a HAMT shard of fanout 16: only 256 is read, as the native node",
        &n,
        bytes(&n),
        fail("unverifiable"),
        None,
    )?;
    let mut hash = Unixfs::new(5);
    hash.hash_type = Some(0x12);
    hash.fanout = Some(256);
    hash.data = Some(vec![0x00]);
    let n = pb_node(&[], Some(&hash.encode()));
    push(
        "hamt-other-hash",
        "a HAMT shard hashed with sha2-256: only murmur3 is read",
        &n,
        bytes(&n),
        fail("unverifiable"),
        None,
    )?;
    let mut sym = Unixfs::new(4);
    sym.data = Some(b"../elsewhere".to_vec());
    let n = pb_node(&[], Some(&sym.encode()));
    push(
        "symlink",
        "a symlink: decoded, and refused by the walk as GatewayCore refuses it",
        &n,
        bytes(&n),
        ok(summary(&sym, 0)),
        None,
    )?;
    // As many blocksizes entries as 2 MiB holds, and no links.
    let mut head = Vec::new();
    pb_varint(1, 2, &mut head);
    let mut inner = head.clone();
    let count = (MAX_BLOCK - 16) / 2;
    for _ in 0..count {
        inner.extend_from_slice(&[0x20, 0x01]);
    }
    let mut node = Vec::new();
    pb_bytes(1, &inner, &mut node);
    let mut prefix = Vec::new();
    prefix.push(0x0a);
    let mut l = inner.len();
    while l >= 0x80 {
        prefix.push((l as u8) | 0x80);
        l >>= 7;
    }
    prefix.push(l as u8);
    prefix.extend_from_slice(&head);
    let (n2, v2) = parts(&[(&prefix[..], &[0x20_u8, 0x01][..], count)]);
    if n2 != node {
        return Err("the blocksizes recipe differs from the node".into());
    }
    push(
        "blocksizes-maximal",
        "2 MiB of one-byte blocksizes entries and no links: past the cap of entries a node may keep",
        &node,
        v2,
        fail("unverifiable"),
        Some("decoder-caps"),
    )?;
    Ok(out)
}

pub async fn build() -> Result<Value, Err> {
    Ok(json!({
        "blocks": blocks()?,
        "dag_pb": dag_pb()?,
        "unixfs": unixfs()?,
        "hamt": hamt().await?,
        "car": car()?,
    }))
}

async fn hamt() -> Result<Vec<Value>, Err> {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(crate::OUT)?)?;
    let dir = doc["ipfs"]["directories"]
        .as_array()
        .and_then(|d| d.iter().find(|x| x["id"] == "hamt-v1"))
        .ok_or("hamt-v1 in dweb-verify.json")?;
    let blocks = &doc["ipfs"]["blocks"];
    let block = |cid: &str| -> Result<Vec<u8>, Err> {
        let b = blocks[cid].as_str().ok_or_else(|| format!("block {cid}"))?;
        Ok(base64::engine::general_purpose::STANDARD.decode(b)?)
    };
    let root = dir["root"].as_str().ok_or("root")?.to_string();
    let mut out = Vec::new();
    let mut names: Vec<String> = dir["entries"]
        .as_array()
        .ok_or("entries")?
        .iter()
        .filter_map(|e| e["path"].as_str().map(str::to_string))
        .collect();
    names.push("not-in-the-directory.txt".to_string());
    for name in names {
        let bits = crate::murmur3::hamt_bits(&name);
        let mut levels = Vec::new();
        let mut cid = root.clone();
        let mut found = Value::Null;
        for (depth, &bucket) in bits.iter().enumerate() {
            let node = crate::car::dag_pb(&block(&cid)?).ok_or("shard isn't dag-pb")?;
            let prefix = format!("{bucket:02X}");
            let hit = node.links.iter().find(|(_, n)| n.starts_with(&prefix));
            match hit {
                None => {
                    levels.push(json!({ "depth": depth, "bucket": bucket, "link": null }));
                    break;
                }
                Some((c, n)) if n.len() == 2 => {
                    levels.push(json!({ "depth": depth, "bucket": bucket, "link": n }));
                    cid = c.to_string();
                }
                Some((c, n)) => {
                    levels.push(json!({ "depth": depth, "bucket": bucket, "link": n }));
                    if n[2..] == name {
                        found = json!(c.to_string());
                    }
                    break;
                }
            }
        }
        let listed = name != "not-in-the-directory.txt";
        if listed == found.is_null() {
            return Err(format!("murmur3 doesn't place {name} where Kubo put it").into());
        }
        out.push(json!({
            "id": format!("hamt-v1/{name}"),
            "root": root,
            "name": name,
            "hash_bits": hex::encode(bits),
            "levels": levels,
            "expect": if listed { ok(json!({ "cid": found })) } else { json!({ "absent": true }) },
        }));
    }
    hamt_misplaced(&doc, dir, &mut out).await?;
    Ok(out)
}

fn car_header(roots: &[&Cid], version: u64, extra: &[u8]) -> Vec<u8> {
    // DAG-CBOR {roots: [cid…], version: n}, keys by length then bytewise.
    let mut h = vec![0xa2 + u8::from(!extra.is_empty())];
    h.extend_from_slice(&[0x65, b'r', b'o', b'o', b't', b's']);
    h.push(0x80 | roots.len() as u8);
    for r in roots {
        let mut b = vec![0x00];
        b.extend_from_slice(&r.to_bytes());
        h.extend_from_slice(&[0xd8, 0x2a, 0x58, b.len() as u8]);
        h.extend_from_slice(&b);
    }
    h.extend_from_slice(extra);
    h.extend_from_slice(&[
        0x67,
        b'v',
        b'e',
        b'r',
        b's',
        b'i',
        b'o',
        b'n',
        version as u8,
    ]);
    let mut out = Vec::new();
    uvarint(h.len() as u64, &mut out);
    out.extend_from_slice(&h);
    out
}

fn uvarint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn section(cid: &Cid, block: &[u8]) -> Vec<u8> {
    let c = cid.to_bytes();
    let mut out = Vec::new();
    uvarint((c.len() + block.len()) as u64, &mut out);
    out.extend_from_slice(&c);
    out.extend_from_slice(block);
    out
}

fn car() -> Result<Vec<Value>, Err> {
    let mut out = Vec::new();
    let mut push = |id: &str, note: &str, body: &[u8], expect: Value, deviation: Option<&str>| {
        let native = match freedom_ipfs_core::parse_car_v1(body) {
            Ok(car) => json!({ "parse_car_v1": { "sections": car.blocks.len() } }),
            Err(e) => json!({ "parse_car_v1": e.to_string() }),
        };
        let mut case = json!({ "id": id, "note": note, "car": bytes(body), "expect": expect, "native": native });
        if let Some(d) = deviation {
            case["deviation"] = json!(d);
        }
        out.push(case);
    };
    let a = crate::content::bytes("checks-car-a", 300);
    let b = crate::content::bytes("checks-car-b", 200);
    let (ca, cb) = (sha256_cid(RAW, &a)?, sha256_cid(RAW, &b)?);
    let mut file = Unixfs::new(2);
    file.filesize = Some(500);
    file.blocksizes = vec![300, 200];
    let root = pb_node(
        &[link(&ca, "", 300), link(&cb, "", 200)],
        Some(&file.encode()),
    );
    let cr = sha256_cid(DAG_PB, &root)?;
    let sections = [section(&cr, &root), section(&ca, &a), section(&cb, &b)];
    let ids = json!([cr.to_string(), ca.to_string(), cb.to_string()]);
    let header = car_header(&[&cr], 1, &[]);
    let honest = [header.clone(), sections.concat()].concat();
    push(
        "honest",
        "a header and three sections",
        &honest,
        ok(json!({ "sections": ids })),
        None,
    );
    let no_roots = [car_header(&[], 1, &[]), sections.concat()].concat();
    push(
        "no-roots",
        "a header with no roots: roots are ignored",
        &no_roots,
        ok(json!({ "sections": ids })),
        None,
    );
    let v2 = [car_header(&[&cr], 2, &[]), sections.concat()].concat();
    push(
        "version-2",
        "a header with version 2",
        &v2,
        json!({ "fail": "verification_failed", "after": 0 }),
        None,
    );
    let pad = vec![0u8; 64 * 1024];
    let mut extra = vec![0x63, b'p', b'a', b'd', 0x5a];
    extra.extend_from_slice(&(pad.len() as u32).to_be_bytes());
    extra.extend_from_slice(&pad);
    // Keys by length: "pad" (3) sorts before "roots" (5); rebuild in order.
    let big = {
        let mut h = vec![0xa3];
        h.extend_from_slice(&extra);
        let rest = car_header(&[&cr], 1, &[]);
        let mut pos = 0;
        let len = varint_at(&rest, &mut pos).ok_or("header length")? as usize;
        // rest[pos + 1] is the map's head; take its entries.
        h.extend_from_slice(&rest[pos + 2..pos + 1 + len]);
        let mut o = Vec::new();
        uvarint(h.len() as u64, &mut o);
        o.extend_from_slice(&h);
        o
    };
    let big_car = [big, sections.concat()].concat();
    push(
        "header-over-64-kib",
        "a header past 64 KiB (an unknown key holding 64 KiB)",
        &big_car,
        json!({ "fail": "verification_failed", "after": 0 }),
        None,
    );
    for (id, depth, expect, dev) in [
        (
            "header-depth-8",
            8usize,
            ok(json!({ "sections": ids })),
            None,
        ),
        (
            "header-depth-9",
            9,
            json!({ "fail": "unverifiable", "after": 0 }),
            Some("decoder-caps"),
        ),
    ] {
        let mut nest = vec![0x63, b'a', b'a', b'a'];
        for _ in 0..depth.saturating_sub(2) {
            nest.extend_from_slice(&[0xa1, 0x61, b'a']);
        }
        nest.push(0xa0);
        let mut h = vec![0xa3];
        h.extend_from_slice(&nest);
        let rest = car_header(&[&cr], 1, &[]);
        let mut pos = 0;
        let len = varint_at(&rest, &mut pos).ok_or("header length")? as usize;
        // rest[pos + 1] is the map's head; take its entries.
        h.extend_from_slice(&rest[pos + 2..pos + 1 + len]);
        let mut o = Vec::new();
        uvarint(h.len() as u64, &mut o);
        o.extend_from_slice(&h);
        let body = [o, sections.concat()].concat();
        push(
            id,
            &format!(
                "a header with an unknown key whose value nests maps {depth} levels deep, the header's map the first"
            ),
            &body,
            expect,
            dev,
        );
    }
    let mut short_header = header.clone();
    short_header[0] = short_header[0].wrapping_add(40);
    let body = [short_header, sections.concat()].concat();
    push(
        "header-length-past-end",
        "a header length 40 bytes too long: the header's CBOR runs into the sections and fails",
        &body,
        json!({ "fail": "verification_failed", "after": 0 }),
        None,
    );
    let mut huge = Vec::new();
    uvarint((3 * 1024 * 1024) as u64, &mut huge);
    huge.extend_from_slice(&ca.to_bytes());
    let body = [header.clone(), sections[0].clone(), huge].concat();
    push(
        "section-past-limit",
        "after one section, a section length of 3 MiB: refused before a byte of it is buffered",
        &body,
        json!({ "fail": "verification_failed", "after": 1 }),
        None,
    );
    let mut long = vec![
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    ];
    long.extend_from_slice(&sections[1][2..]);
    let body = [header.clone(), sections[0].clone(), long].concat();
    push(
        "varint-11-bytes",
        "after one section, a section length in 11 bytes",
        &body,
        json!({ "fail": "verification_failed", "after": 1 }),
        None,
    );
    let mut bad = sections[1].clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    let body = [
        header.clone(),
        sections[0].clone(),
        bad,
        sections[2].clone(),
    ]
    .concat();
    push(
        "block-mismatch",
        "the second section's block with its last byte flipped",
        &body,
        json!({ "fail": "verification_failed", "after": 1 }),
        None,
    );
    let mut bad_cid = sections[1].clone();
    let p = bad_cid
        .iter()
        .position(|&x| x == 0x01)
        .ok_or("cid version")?;
    bad_cid[p] = 0x07;
    let body = [header.clone(), sections[0].clone(), bad_cid].concat();
    push(
        "section-cid-version-7",
        "the second section's CID with version 7",
        &body,
        json!({ "fail": "verification_failed", "after": 1 }),
        None,
    );
    let body = [
        header.clone(),
        sections[0].clone(),
        sections[1][..50].to_vec(),
    ]
    .concat();
    push(
        "ends-inside-a-section",
        "the stream ends 50 bytes into the second section: an early end, which the walk takes as a piece failure",
        &body,
        json!({ "ended": { "after": 1 } }),
        None,
    );
    let marker = b"\n\n[Gateway Error: CAR stream truncated, response is incomplete]";
    let body = [header.clone(), sections[0].clone(), marker.to_vec()].concat();
    push(
        "boxo-truncation-marker",
        "after one section, the marker boxo appends to a CAR that fails partway (ipfs/boxo#1197): an early end, not a lie",
        &body,
        json!({ "ended": { "after": 1 } }),
        None,
    );
    let body = [header.clone(), sections[0].clone()].concat();
    push(
        "ends-between-sections",
        "the stream ends after the first section: the reader is done, and the walk fetches the blocks it still needs raw",
        &body,
        ok(json!({ "sections": [cr.to_string()] })),
        None,
    );
    // Bounded CBOR (0009, Bounded decoding): each header changes the
    // honest one in one way the reader refuses.
    let tag42 = |c: &Cid| {
        let mut b = vec![0x00];
        b.extend_from_slice(&c.to_bytes());
        let mut out = vec![0xd8, 0x2a, 0x58, b.len() as u8];
        out.extend_from_slice(&b);
        out
    };
    let roots_key = vec![0x65, b'r', b'o', b'o', b't', b's'];
    let roots_kv = [roots_key.clone(), vec![0x81], tag42(&cr)].concat();
    let version_kv = vec![0x67, b'v', b'e', b'r', b's', b'i', b'o', b'n', 0x01];
    let pad_key = vec![0x63, b'p', b'a', b'd'];
    let framed = |cbor: Vec<u8>| {
        let mut o = Vec::new();
        uvarint(cbor.len() as u64, &mut o);
        o.extend_from_slice(&cbor);
        [o, sections.concat()].concat()
    };
    if framed([vec![0xa2], roots_kv.clone(), version_kv.clone()].concat()) != honest {
        return Err("the CBOR cases' header differs from the honest one".into());
    }
    let mut indefinite_bytes = vec![0xd8, 0x2a, 0x5f];
    indefinite_bytes.extend_from_slice(&tag42(&cr)[2..]);
    indefinite_bytes.push(0xff);
    for (id, note, cbor) in [
        (
            "header-indefinite-map",
            "the header's map with an indefinite length",
            [vec![0xbf], roots_kv.clone(), version_kv.clone(), vec![0xff]].concat(),
        ),
        (
            "header-indefinite-array",
            "the roots array with an indefinite length",
            [
                vec![0xa2],
                roots_key.clone(),
                vec![0x9f],
                tag42(&cr),
                vec![0xff],
                version_kv.clone(),
            ]
            .concat(),
        ),
        (
            "header-indefinite-key",
            "the key roots as an indefinite-length text string",
            [
                vec![0xa2, 0x7f],
                roots_key.clone(),
                vec![0xff, 0x81],
                tag42(&cr),
                version_kv.clone(),
            ]
            .concat(),
        ),
        (
            "header-indefinite-cid",
            "the root's CID bytes as an indefinite-length byte string",
            [
                vec![0xa2],
                roots_key.clone(),
                vec![0x81],
                indefinite_bytes.clone(),
                version_kv.clone(),
            ]
            .concat(),
        ),
        (
            "header-integer-key",
            "an entry whose key is the integer 1",
            [vec![0xa3, 0x01, 0x01], roots_kv.clone(), version_kv.clone()].concat(),
        ),
        (
            "header-integer-key-nested",
            "an unknown key whose value is a map with an integer key",
            [
                vec![0xa3],
                pad_key.clone(),
                vec![0xa1, 0x01, 0x01],
                roots_kv.clone(),
                version_kv.clone(),
            ]
            .concat(),
        ),
        (
            "header-duplicate-key",
            "version twice, with the same value",
            [
                vec![0xa3],
                roots_kv.clone(),
                version_kv.clone(),
                version_kv.clone(),
            ]
            .concat(),
        ),
        (
            "header-tag-42-not-bytes",
            "an unknown key whose value is tag 42 over an integer: not a CID",
            [
                vec![0xa3],
                pad_key.clone(),
                vec![0xd8, 0x2a, 0x01],
                roots_kv.clone(),
                version_kv.clone(),
            ]
            .concat(),
        ),
        (
            "header-tag-42-no-prefix",
            "a root as tag 42 over the CID's bytes without the 0x00 prefix",
            [
                vec![0xa2],
                roots_key.clone(),
                vec![0x81, 0xd8, 0x2a, 0x58, cr.to_bytes().len() as u8],
                cr.to_bytes(),
                version_kv.clone(),
            ]
            .concat(),
        ),
        (
            "header-tag-42-not-a-cid",
            "a root as tag 42 over 0x00 and bytes that aren't a CID",
            [
                vec![0xa2],
                roots_key.clone(),
                vec![0x81, 0xd8, 0x2a, 0x44, 0x00, 0x07, 0x07, 0x07],
                version_kv.clone(),
            ]
            .concat(),
        ),
        (
            "header-other-tag",
            "an unknown key whose value is tag 1 (an epoch time): DAG-CBOR has only tag 42",
            [
                vec![0xa3],
                pad_key.clone(),
                vec![0xc1, 0x00],
                roots_kv.clone(),
                version_kv.clone(),
            ]
            .concat(),
        ),
    ] {
        push(
            id,
            note,
            &framed(cbor),
            json!({ "fail": "verification_failed", "after": 0 }),
            None,
        );
    }
    push(
        "header-unknown-key",
        "an unknown key with a text value: skipped, as the CBOR rules allow",
        &framed(
            [
                vec![0xa3],
                pad_key.clone(),
                vec![0x61, b'x'],
                roots_kv.clone(),
                version_kv.clone(),
            ]
            .concat(),
        ),
        ok(json!({ "sections": ids })),
        None,
    );
    push(
        "header-tag-42-unknown-key",
        "an unknown key whose value is a CID (tag 42): a link where DAG-CBOR allows one, skipped",
        &framed(
            [
                vec![0xa3],
                pad_key.clone(),
                tag42(&cr),
                roots_kv.clone(),
                version_kv.clone(),
            ]
            .concat(),
        ),
        ok(json!({ "sections": ids })),
        None,
    );
    push(
        "header-tag-42-nested",
        "an unknown key whose value is a map holding a CID (tag 42), skipped",
        &framed(
            [
                vec![0xa3],
                pad_key.clone(),
                vec![0xa1, 0x61, b'a'],
                tag42(&cr),
                roots_kv.clone(),
                version_kv.clone(),
            ]
            .concat(),
        ),
        ok(json!({ "sections": ids })),
        None,
    );
    let idc = identity_cid(b"abc")?;
    let body = [header.clone(), section(&idc, b"abd")].concat();
    push(
        "identity-section-mismatch",
        "a section with an identity CID whose block isn't its digest",
        &body,
        json!({ "fail": "verification_failed", "after": 0 }),
        None,
    );
    Ok(out)
}

fn varint_at(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *buf.get(*pos)?;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        *pos += 1;
        shift += 7;
    }
}

/// A protobuf message's fields: number, wire type, and the value's bytes
/// (a varint's encoding, or a length-delimited field's contents).
fn pb_fields(buf: &[u8]) -> Result<Vec<(u64, u8, Vec<u8>)>, Err> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let key = varint_at(buf, &mut pos).ok_or("field key")?;
        pos += 1;
        let wt = (key & 7) as u8;
        match wt {
            0 => {
                let start = pos;
                varint_at(buf, &mut pos).ok_or("varint")?;
                pos += 1;
                out.push((key >> 3, wt, buf[start..pos].to_vec()));
            }
            2 => {
                let len = varint_at(buf, &mut pos).ok_or("length")? as usize;
                pos += 1;
                out.push((
                    key >> 3,
                    wt,
                    buf.get(pos..pos + len).ok_or("past end")?.to_vec(),
                ));
                pos += len;
            }
            _ => return Err("an unexpected wire type".into()),
        }
    }
    Ok(out)
}

fn varint_value(b: &[u8]) -> u64 {
    let mut pos = 0;
    varint_at(b, &mut pos).unwrap_or(0)
}

/// A HAMT shard's links (hash, name, tsize) and its bitfield.
fn shard_parts(block: &[u8]) -> Result<(Vec<Link>, Vec<u8>), Err> {
    let mut links = Vec::new();
    let mut bitfield = None;
    for (num, _, v) in pb_fields(block)? {
        match num {
            2 => {
                let mut l = Link {
                    hash: None,
                    name: None,
                    tsize: None,
                };
                for (n, _, f) in pb_fields(&v)? {
                    match n {
                        1 => l.hash = Some(f),
                        2 => l.name = Some(String::from_utf8(f)?),
                        3 => l.tsize = Some(varint_value(&f)),
                        _ => return Err("an unknown link field".into()),
                    }
                }
                links.push(l);
            }
            1 => {
                for (n, _, f) in pb_fields(&v)? {
                    match n {
                        1 if varint_value(&f) != 5 => return Err("not a HAMT shard".into()),
                        2 => bitfield = Some(f),
                        5 if varint_value(&f) != 0x22 => return Err("not murmur3".into()),
                        6 if varint_value(&f) != 256 => return Err("not fanout 256".into()),
                        _ => {}
                    }
                }
            }
            _ => return Err("an unknown node field".into()),
        }
    }
    Ok((links, bitfield.ok_or("no bitfield")?))
}

fn shard_block(links: &[Link], bitfield: &[u8]) -> Vec<u8> {
    let mut data = Unixfs::new(5);
    data.data = Some(bitfield.to_vec());
    data.hash_type = Some(0x22);
    data.fanout = Some(256);
    pb_node(links, Some(&data.encode()))
}

/// Bucket `i` of a big-endian, right-aligned bitfield.
fn bit(bitfield: &[u8], i: u8) -> bool {
    let byte = usize::from(i / 8);
    byte < bitfield.len() && (bitfield[bitfield.len() - 1 - byte] >> (i % 8)) & 1 == 1
}

fn set_bit(bitfield: &mut [u8], i: u8, on: bool) {
    let at = bitfield.len() - 1 - usize::from(i / 8);
    if on {
        bitfield[at] |= 1 << (i % 8);
    } else {
        bitfield[at] &= !(1 << (i % 8));
    }
}

/// GatewayCore's answer for a path over these blocks: the native reader.
async fn native_get(blocks: HashMap<Cid, Vec<u8>>, path: &str) -> Result<Value, Err> {
    let core = freedom_ipfs_gateway::GatewayCore::with_provider_config(
        std::sync::Arc::new(crate::ipfs::MemProvider(blocks)),
        freedom_ipfs_gateway::GatewayConfig::new(8),
    );
    let parsed = freedom_ipfs_gateway::parse_native_request(freedom_ipfs_gateway::NativeRequest {
        method: Some("GET".to_string()),
        path: path.to_string(),
        headers: Some(Vec::new()),
        request_id: Some(1),
        parent_request_id: None,
        top_level_path: Some(path.to_string()),
    })
    .map_err(|e| e.to_string())?;
    let resp = core.handle(parsed.request).await;
    let status = resp.status().as_u16();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok(
        json!({ "status": status, "length": body.len(), "sha256": hex::encode(Sha256::digest(&body)) }),
    )
}

/// hamt-lookup's cases: an entry that isn't where its hash and the
/// bitfield point, in a root shard rebuilt from hamt-v1's. The native
/// reader finds it by name; the core follows the hash and answers absent.
async fn hamt_misplaced(doc: &Value, dir: &Value, out: &mut Vec<Value>) -> Result<(), Err> {
    let blocks = &doc["ipfs"]["blocks"];
    let mut all = HashMap::new();
    for (cid, b) in blocks.as_object().ok_or("blocks")? {
        all.insert(
            Cid::try_from(cid.as_str())?,
            base64::engine::general_purpose::STANDARD.decode(b.as_str().ok_or("block")?)?,
        );
    }
    // The entries' leaves, from their seeded content.
    for e in dir["entries"].as_array().ok_or("entries")? {
        let seed = e["seed"].as_str().ok_or("an entry without a seed")?;
        for l in e["leaves"].as_array().ok_or("leaves")? {
            let (from, len) = (
                l["from"].as_u64().ok_or("from")? as usize,
                l["length"].as_u64().ok_or("length")? as usize,
            );
            let data = crate::content::bytes(seed, from + len)[from..].to_vec();
            all.insert(Cid::try_from(l["cid"].as_str().ok_or("cid")?)?, data);
        }
    }
    let root = dir["root"].as_str().ok_or("root")?;
    let root_block = all.get(&Cid::try_from(root)?).ok_or("root block")?.clone();
    // GatewayCore finds hamt-v1's own entries.
    let honest = native_get(
        all.clone(),
        &format!(
            "/ipfs/{root}/{}",
            dir["entries"][0]["path"].as_str().ok_or("path")?
        ),
    )
    .await?;
    if honest["status"] != 200 {
        return Err(format!("GatewayCore doesn't find hamt-v1's entry: {honest}").into());
    }
    let (links, bitfield) = shard_parts(&root_block)?;
    if shard_block(&links, &bitfield) != root_block {
        return Err("the HAMT rebuild doesn't give Kubo's root shard back".into());
    }
    // Two entries at the root, in different buckets.
    let entries: Vec<usize> = links
        .iter()
        .enumerate()
        .filter(|(_, l)| l.name.as_deref().is_some_and(|n| n.len() > 2))
        .map(|(i, _)| i)
        .take(2)
        .collect();
    let [first, second] = entries[..] else {
        return Err("hamt-v1's root holds fewer than two entries".into());
    };
    let name_of = |l: &Link| -> Result<(u8, String), Err> {
        let n = l.name.as_deref().ok_or("name")?;
        Ok((u8::from_str_radix(&n[..2], 16)?, n[2..].to_string()))
    };
    let (bucket, name) = name_of(&links[first])?;
    if crate::murmur3::hamt_bits(&name)[0] != bucket {
        return Err("hamt-v1's entry isn't in its hash's bucket".into());
    }
    let empty = (0..=255u8)
        .find(|&b| !bit(&bitfield, b))
        .ok_or("a full root shard")?;
    let mut push = |id: &str,
                    note: &str,
                    links: &[Link],
                    bitfield: &[u8],
                    name: &str,
                    bucket: u8,
                    native: Value|
     -> Result<(), Err> {
        let block = shard_block(links, bitfield);
        let cid = sha256_cid(DAG_PB, &block)?;
        out.push(json!({
            "id": id,
            "note": note,
            "root": cid.to_string(),
            "blocks": { cid.to_string(): base64::engine::general_purpose::STANDARD.encode(&block) },
            "name": name,
            "hash_bits": hex::encode(crate::murmur3::hamt_bits(name)),
            "levels": [{ "depth": 0, "bucket": bucket, "link": null }],
            "expect": { "absent": true },
            "deviation": "hamt-lookup",
            "native": native,
        }));
        Ok(())
    };
    // The entry renamed into an empty bucket, the bitfield moved with it.
    let mut moved: Vec<Link> = links
        .iter()
        .map(|l| Link {
            hash: l.hash.clone(),
            name: l.name.clone(),
            tsize: l.tsize,
        })
        .collect();
    moved[first].name = Some(format!("{empty:02X}{name}"));
    moved.sort_by(|a, b| a.name.cmp(&b.name));
    let mut bf = bitfield.clone();
    set_bit(&mut bf, bucket, false);
    set_bit(&mut bf, empty, true);
    let block = shard_block(&moved, &bf);
    let mut with = all.clone();
    let cid = sha256_cid(DAG_PB, &block)?;
    with.insert(cid, block);
    let native = native_get(with, &format!("/ipfs/{cid}/{name}")).await?;
    if native["status"] != 200 {
        return Err(format!("GatewayCore didn't find the moved entry: {native}").into());
    }
    push(
        &format!("hamt-v1-moved/{name}"),
        &format!(
            "hamt-v1's root with the entry for {name} moved from bucket {bucket:02X}, where its hash points, to the empty bucket {empty:02X}, the bitfield moved with it: the native reader finds it by name, the core's lookup finds the bucket empty"
        ),
        &moved,
        &bf,
        &name,
        bucket,
        native,
    )?;
    // Two entries' links swapped, names and bitfield unchanged.
    let mut swapped: Vec<Link> = links
        .iter()
        .map(|l| Link {
            hash: l.hash.clone(),
            name: l.name.clone(),
            tsize: l.tsize,
        })
        .collect();
    swapped.swap(first, second);
    let block = shard_block(&swapped, &bitfield);
    let mut with = all.clone();
    let cid = sha256_cid(DAG_PB, &block)?;
    with.insert(cid, block);
    let native = native_get(with, &format!("/ipfs/{cid}/{name}")).await?;
    if native["status"] != 200 {
        return Err(format!("GatewayCore didn't find the swapped entry: {native}").into());
    }
    push(
        &format!("hamt-v1-swapped/{name}"),
        &format!(
            "hamt-v1's root with the links of its first two entries swapped: at bucket {bucket:02X}'s position among the set bits is another bucket's link, so the core's lookup of {name} finds no entry there, where the native reader finds it by name"
        ),
        &swapped,
        &bitfield,
        &name,
        bucket,
        native,
    )?;
    Ok(())
}
