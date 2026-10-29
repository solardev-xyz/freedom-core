//! IPFS piece checks: blocks against their CIDs, dag-pb and UnixFS decoding
//! with the bounded decoders' caps, HAMT lookup by hash, and CAR framing
//! (0009, Blocks and DAGs, Bounded decoding, The CAR request).

use super::{Err, bytes, fail, ok, parts};
use crate::ipns::{pb_bytes, pb_varint};
use base64::Engine;
use cid::Cid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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
    let mut push =
        |id: &str, note: &str, cid: &Cid, block: &[u8], block_v: Value, expect: Value| {
            out.push(json!({
                "id": id,
                "note": note,
                "cid": cid.to_string(),
                "block": block_v,
                "expect": expect,
                "native": native(cid, block),
            }));
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
    );
    let mut flipped = raw.clone();
    flipped[500] ^= 0x01;
    push(
        "raw-flipped",
        "the raw block with byte 500 flipped",
        &c,
        &flipped,
        bytes(&flipped),
        fail("verification_failed"),
    );
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
    );
    let c1 = sha256_cid(DAG_PB, &node)?;
    push(
        "dag-pb-v1",
        "the same node and its CIDv1: a link matches a block when codec and multihash agree",
        &c1,
        &node,
        bytes(&node),
        ok(json!({ "codec": "dag-pb" })),
    );
    let id = identity_cid(b"hello")?;
    push(
        "identity",
        "an identity CID: its block is its digest",
        &id,
        b"hello",
        bytes(b"hello"),
        ok(json!({ "codec": "raw" })),
    );
    push(
        "identity-mismatch",
        "an identity CID with other bytes",
        &id,
        b"hellp",
        bytes(b"hellp"),
        fail("verification_failed"),
    );
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
    );
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
    );
    let blake3 = Cid::new_v1(RAW, mh(0x1e, &Sha256::digest(&raw))?);
    push(
        "blake3",
        "a blake3 CID (its digest arbitrary): an unsupported hash",
        &blake3,
        &raw,
        bytes(&raw),
        fail("unverifiable"),
    );
    let sha512 = Cid::new_v1(RAW, mh(0x13, &[0u8; 64])?);
    push(
        "sha2-512",
        "a sha2-512 CID: an unsupported hash",
        &sha512,
        &raw,
        bytes(&raw),
        fail("unverifiable"),
    );
    let truncated = Cid::new_v1(RAW, mh(0x12, &Sha256::digest(&raw)[..20])?);
    push(
        "sha2-256-short-digest",
        "a sha2-256 CID whose digest is the real one's first 20 bytes",
        &truncated,
        &raw,
        bytes(&raw),
        fail("verification_failed"),
    );
    let cbor = sha256_cid(0x71, &raw)?;
    push(
        "dag-cbor",
        "a dag-cbor CID whose hash matches: only dag-pb and raw are read",
        &cbor,
        &raw,
        bytes(&raw),
        fail("unverifiable"),
    );
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

pub fn build() -> Result<Value, Err> {
    Ok(json!({
        "blocks": blocks()?,
        "dag_pb": dag_pb()?,
        "unixfs": unixfs()?,
        "hamt": hamt()?,
        "car": car()?,
    }))
}

fn hamt() -> Result<Vec<Value>, Err> {
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
                    if &n[2..] == name {
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
        "the stream ends after the first section: the reader is done, and the walk, still missing blocks, takes it as a piece failure",
        &body,
        ok(json!({ "sections": [cr.to_string()] })),
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
