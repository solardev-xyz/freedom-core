//! The verifier's IPFS walk (design 0009, step 3b-2) against an honest
//! trustless gateway over dweb-verify.json's blocks, as main and the
//! hashing pool drive it:
//!
//! - the gateway's CARs are a conforming trustless gateway's (the path's
//!   blocks, then the entity, depth-first with duplicates, only the blocks
//!   covering `entity-bytes`), held to Kubo's recorded answers;
//! - every native exchange in dweb-verify.json (GatewayCore's answers)
//!   reproduced through it, with the design's deviations named;
//! - every `ipfs/*` and `ipns/*` request case of dweb-verify-cases.json
//!   (IPNS floors are 3c's).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, HashMap};

use fc_dweb::verifier::{Method, PieceRequest};
use fc_dweb::{
    Backend, ContentTrust, Ipfs, Node, ResponseOp, Root, Trust, Verify, cid_v0_to_v1_base32, retry,
    timers,
};
use fc_ipfs::cid as ipfs_cid;
use serde_json::Value as Json;

mod common;
use common::{Answer, Ending, Expected, Opts, Order, b64, check_body, content, load, pairs, run};

/// A block's identity: its codec and multihash, so a CIDv0 link and its
/// CIDv1 name the same block.
type Key = (u64, u64, Vec<u8>);

fn key(cid: &[u8]) -> Key {
    let c = ipfs_cid::parse(cid).unwrap_or_else(|| panic!("a CID: {cid:?}"));
    (c.codec, c.hash, c.digest.to_vec())
}

/// A CID's bytes from its text: a CIDv0, or a CIDv1 in base32.
fn cid_bytes(text: &str) -> Vec<u8> {
    let v1 = if text.starts_with("Qm") {
        cid_v0_to_v1_base32(text).unwrap()
    } else {
        text.to_ascii_lowercase()
    };
    ipfs_cid::from_base32(&v1).unwrap_or_else(|| panic!("{text}"))
}

/// The plan's canonical root for a CID's text.
fn canonical(text: &str) -> String {
    cid_v0_to_v1_base32(text).unwrap_or_else(|| text.to_ascii_lowercase())
}

/// The vectors' blocks and records.
#[derive(Clone)]
struct Blocks {
    blocks: HashMap<Key, Vec<u8>>,
    /// Each name's record, as the native resolver held it, and its value.
    records: HashMap<String, Vec<u8>>,
    values: HashMap<String, String>,
}

impl Blocks {
    fn new(doc: &Json) -> Self {
        let i = &doc["ipfs"];
        let mut blocks = HashMap::new();
        for (cid, b) in i["blocks"].as_object().unwrap() {
            blocks.insert(key(&cid_bytes(cid)), b64(b));
        }
        let add_file = |f: &Json, blocks: &mut HashMap<Key, Vec<u8>>| {
            let size = f["size"].as_u64().unwrap() as usize;
            let body = if let Some(c) = f.get("content").filter(|c| c.is_object()) {
                let unit = content(
                    c["seed"].as_str().unwrap(),
                    c["unit"].as_u64().unwrap() as usize,
                );
                unit.repeat(c["count"].as_u64().unwrap() as usize)
            } else if let Some(t) = f["text"].as_str() {
                t.as_bytes().to_vec()
            } else {
                content(f["seed"].as_str().unwrap(), size)
            };
            for l in f["leaves"].as_array().unwrap() {
                let from = l["from"].as_u64().unwrap() as usize;
                let len = l["length"].as_u64().unwrap() as usize;
                let slice = &body[from..from + len];
                let block = match l.get("prefix") {
                    Some(p) => {
                        let mut b = b64(p);
                        b.extend_from_slice(slice);
                        b.extend_from_slice(&b64(&l["suffix"]));
                        b
                    }
                    None => slice.to_vec(),
                };
                blocks.insert(key(&cid_bytes(l["cid"].as_str().unwrap())), block);
            }
        };
        for f in i["files"].as_array().unwrap() {
            add_file(f, &mut blocks);
        }
        for d in i["directories"].as_array().unwrap() {
            for e in d["entries"].as_array().unwrap() {
                add_file(e, &mut blocks);
            }
        }
        let mut records = HashMap::new();
        let mut values = HashMap::new();
        let mut best: HashMap<String, u64> = HashMap::new();
        for r in i["ipns"]["records"].as_array().unwrap() {
            let name = r["name"].as_str().unwrap().to_owned();
            if let Some(ok) = r["native"].get("ok") {
                let seq = ok["sequence"].as_u64().unwrap();
                if best.get(&name).is_none_or(|&b| seq > b) {
                    best.insert(name.clone(), seq);
                    values.insert(name.clone(), ok["value"].as_str().unwrap().to_owned());
                    records.insert(name, b64(&r["record"]));
                }
            }
        }
        Self {
            blocks,
            records,
            values,
        }
    }

    fn get(&self, cid: &[u8]) -> Option<Vec<u8>> {
        let c = ipfs_cid::parse(cid)?;
        if c.hash == ipfs_cid::IDENTITY {
            return Some(c.digest.to_vec());
        }
        self.blocks.get(&key(cid)).cloned()
    }
}

/// A node's links: (CID bytes, name, Tsize).
fn links(block: &[u8]) -> Vec<(Vec<u8>, String, Option<u64>)> {
    let node = fc_ipfs::dagpb::decode(block).unwrap();
    node.links()
        .map(|l| {
            (
                l.cid.bytes.to_vec(),
                l.name.unwrap_or("").to_owned(),
                l.tsize,
            )
        })
        .collect()
}

fn kind(cid: &[u8], block: &[u8]) -> fc_ipfs::unixfs::Kind {
    if ipfs_cid::parse(cid).unwrap().codec == ipfs_cid::RAW {
        return fc_ipfs::unixfs::Kind::Raw;
    }
    let node = fc_ipfs::dagpb::decode(block).unwrap();
    // A node the core's reader refuses: sent alone, as a file's root.
    fc_ipfs::unixfs::decode(&node).map_or(fc_ipfs::unixfs::Kind::Raw, |d| d.kind)
}

/// The blocks a conforming trustless gateway sends for `root`'s `path` with
/// `dag-scope=entity`: the path's, then the entity's, depth-first with
/// duplicates, only those covering `entity-bytes`. `None` for a path that
/// doesn't resolve.
fn car_blocks(
    b: &Blocks,
    root: &[u8],
    segments: &[String],
    bytes: Option<(i64, Option<u64>)>,
) -> Option<Vec<Vec<u8>>> {
    use fc_ipfs::unixfs::Kind;
    let mut out = Vec::new();
    let mut at = root.to_vec();
    for seg in segments {
        let block = b.get(&at)?;
        if ipfs_cid::parse(&at)?.hash != ipfs_cid::IDENTITY {
            out.push(at.clone());
        }
        match kind(&at, &block) {
            Kind::Directory => {
                // A missing name: the CAR up to its parent, and its end.
                let Some(l) = links(&block).into_iter().find(|l| &l.1 == seg) else {
                    return Some(out);
                };
                at = l.0;
            }
            Kind::HamtShard => {
                let mut shard = block;
                let mut level = 0;
                loop {
                    let node = fc_ipfs::dagpb::decode(&shard).unwrap();
                    let data = fc_ipfs::unixfs::decode(&node).unwrap();
                    match fc_ipfs::hamt::step(&node, data.data.unwrap_or(&[]), seg, level) {
                        fc_ipfs::hamt::Step::Entry(l) => {
                            at = l.cid.bytes.to_vec();
                            break;
                        }
                        fc_ipfs::hamt::Step::Shard(l) => {
                            out.push(l.cid.bytes.to_vec());
                            shard = b.get(l.cid.bytes)?;
                            level += 1;
                        }
                        fc_ipfs::hamt::Step::Absent => return Some(out),
                    }
                }
            }
            _ => return Some(out),
        }
    }
    // The entity.
    let block = b.get(&at)?;
    match kind(&at, &block) {
        Kind::Directory => out.push(at),
        Kind::HamtShard => shards(b, &at, &mut out),
        _ => {
            let size = file_size(b, &at);
            let (from, to) = match bytes {
                None => (0, size.saturating_sub(1)),
                Some((f, t)) => {
                    let from = if f < 0 {
                        size.saturating_sub(f.unsigned_abs())
                    } else {
                        f as u64
                    };
                    (from, t.unwrap_or(u64::MAX).min(size.saturating_sub(1)))
                }
            };
            file_blocks(b, &at, 0, from, to, &mut out);
        }
    }
    Some(out)
}

fn shards(b: &Blocks, at: &[u8], out: &mut Vec<Vec<u8>>) {
    out.push(at.to_vec());
    let block = b.get(at).unwrap();
    for (cid, name, _) in links(&block) {
        if name.len() == 2 {
            shards(b, &cid, out);
        }
    }
}

fn file_size(b: &Blocks, cid: &[u8]) -> u64 {
    let block = b.get(cid).unwrap();
    if ipfs_cid::parse(cid).unwrap().codec == ipfs_cid::RAW {
        return block.len() as u64;
    }
    let node = fc_ipfs::dagpb::decode(&block).unwrap();
    fc_ipfs::unixfs::decode(&node).map_or(0, |d| d.filesize.unwrap_or(0))
}

/// A file node's blocks covering `from..=to` of its content at `start`.
fn file_blocks(b: &Blocks, cid: &[u8], start: u64, from: u64, to: u64, out: &mut Vec<Vec<u8>>) {
    if ipfs_cid::parse(cid).unwrap().hash != ipfs_cid::IDENTITY {
        out.push(cid.to_vec());
    }
    if ipfs_cid::parse(cid).unwrap().codec == ipfs_cid::RAW {
        return;
    }
    let block = b.get(cid).unwrap();
    let node = fc_ipfs::dagpb::decode(&block).unwrap();
    let Ok(data) = fc_ipfs::unixfs::decode(&node) else {
        return;
    };
    let mut at = start + data.data.map_or(0, |d| d.len() as u64);
    for (l, size) in node.links().zip(data.blocksizes()) {
        let s = at;
        at += size;
        if size == 0 || s + size <= from || s > to {
            continue;
        }
        file_blocks(b, l.cid.bytes, s, from, to, out);
    }
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// A CAR v1's header: `{roots: [root], version}`, in DAG-CBOR.
fn car_header(root: &[u8], version: u8) -> Vec<u8> {
    let mut h = vec![0xa2, 0x65];
    h.extend_from_slice(b"roots");
    // Bytes of 0x00 and the CID, its length in the shortest form.
    let n = root.len() + 1;
    h.extend_from_slice(&[0x81, 0xd8, 0x2a]);
    if n < 24 {
        h.push(0x40 + n as u8);
    } else {
        h.extend_from_slice(&[0x58, n as u8]);
    }
    h.push(0x00);
    h.extend_from_slice(root);
    h.push(0x67);
    h.extend_from_slice(b"version");
    h.push(version);
    let mut out = Vec::new();
    varint(h.len() as u64, &mut out);
    out.extend_from_slice(&h);
    out
}

fn section(cid: &[u8], block: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint((cid.len() + block.len()) as u64, &mut out);
    out.extend_from_slice(cid);
    out.extend_from_slice(block);
    out
}

/// The query's `entity-bytes`: from (negative from the end) and to (`*`:
/// none).
fn entity_bytes(query: &str) -> Option<(i64, Option<u64>)> {
    let v = query
        .split('&')
        .find_map(|p| p.strip_prefix("entity-bytes="))?;
    let (f, t) = v.split_once(':').unwrap();
    Some((
        f.parse().unwrap(),
        if t == "*" {
            None
        } else {
            Some(t.parse().unwrap())
        },
    ))
}

/// Percent-decoding a segment once, as gateways decode paths.
fn decode(seg: &str) -> String {
    let hex = |c: u8| char::from(c).to_digit(16).map(|d| d as u8);
    let b = seg.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 3 <= b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The honest gateway with one case's changes.
struct Gateway<'b> {
    blocks: &'b Blocks,
    changes: Vec<Json>,
}

impl Gateway<'_> {
    fn change(&self, piece: &str) -> Option<&Json> {
        self.changes.iter().find(|c| c["piece"] == piece)
    }
}

impl common::World for Gateway<'_> {
    fn answer(&self, req: &PieceRequest) -> Answer {
        let accept = req
            .headers
            .iter()
            .find(|(n, _)| n == "accept")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let (path, query) = req.path.split_once('?').unwrap();
        if let Some(name) = path.strip_prefix("/ipns/") {
            assert_eq!(query, "format=ipns-record");
            assert_eq!(accept, "application/vnd.ipfs.ipns-record");
            let record = self
                .changes
                .iter()
                .find(|c| c["piece"] == "record" && c["name"] == name)
                .map(|c| b64(&c["record"]["base64"]))
                .or_else(|| self.blocks.records.get(name).cloned());
            return match record {
                Some(r) => Answer::Whole {
                    status: 200,
                    headers: vec![],
                    body: r,
                },
                None => Answer::Whole {
                    status: 404,
                    headers: vec![],
                    body: b"no record".to_vec(),
                },
            };
        }
        let rest = path.strip_prefix("/ipfs/").unwrap();
        let (cid_text, below) = rest.split_once('/').unwrap_or((rest, ""));
        let cid = cid_bytes(cid_text);
        if query == "format=raw" {
            assert_eq!(accept, "application/vnd.ipld.raw");
            assert!(below.is_empty());
            let c = self.changes.iter().find(|c| {
                c["piece"] == "raw" && key(&cid_bytes(c["cid"].as_str().unwrap())) == key(&cid)
            });
            if let Some(c) = c {
                if let Some(s) = c["status"].as_u64() {
                    return stream(s as u16, "text/plain", b64(&c["body"]["base64"]));
                }
                let other = self
                    .blocks
                    .get(&cid_bytes(c["as"].as_str().unwrap()))
                    .unwrap();
                return stream(200, "application/vnd.ipld.raw", other);
            }
            return match self.blocks.get(&cid) {
                Some(b) => stream(200, "application/vnd.ipld.raw", b),
                None => stream(404, "text/plain", b"not found".to_vec()),
            };
        }
        assert!(
            query.starts_with("format=car&dag-scope=entity"),
            "{}",
            req.path
        );
        assert_eq!(
            accept,
            "application/vnd.ipld.car; version=1; order=dfs; dups=y"
        );
        let c = self.change("car");
        if let Some(s) = c.and_then(|c| c["status"].as_u64()) {
            return stream(s as u16, "text/plain", b64(&c.unwrap()["body"]["base64"]));
        }
        // The path as Go's path.Clean reads it.
        let mut segments: Vec<String> = Vec::new();
        for seg in below.split('/').filter(|s| !s.is_empty()).map(decode) {
            match seg.as_str() {
                "." => {}
                ".." => {
                    segments.pop();
                }
                _ => segments.push(seg),
            }
        }
        if let Some(p) = c.and_then(|c| c["answer"]["path_as"].as_str()) {
            segments = p
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
        }
        let mut range = entity_bytes(query);
        if c.is_some_and(|c| c["answer"] == "whole_dag") {
            range = None;
        }
        let Some(mut list) = car_blocks(self.blocks, &cid, &segments, range) else {
            return stream(404, "text/plain", b"not found".to_vec());
        };
        let mut dups = "y";
        if c.is_some_and(|c| c["answer"] == "no_dups" || c["answer"] == "no_dups_unannounced") {
            let mut seen = Vec::new();
            list.retain(|b| {
                let k = key(b);
                if seen.contains(&k) {
                    false
                } else {
                    seen.push(k);
                    true
                }
            });
            if c.unwrap()["answer"] == "no_dups" {
                dups = "n";
            }
        }
        if c.is_some_and(|c| c["answer"] == "reversed") {
            list.reverse();
        }
        let version = c.and_then(|c| c["header_version"].as_u64()).unwrap_or(1) as u8;
        let mut body = car_header(&cid, version);
        let mut sections: Vec<Vec<u8>> = list
            .iter()
            .map(|b| {
                let mut block = self.blocks.get(b).unwrap();
                if let Some(f) = c.and_then(|c| c.get("flip"))
                    && key(&cid_bytes(f["cid"].as_str().unwrap())) == key(b)
                {
                    block[f["offset"].as_u64().unwrap() as usize] ^= 1;
                }
                section(b, &block)
            })
            .collect();
        if let Some(n) = c.and_then(|c| c["end_after_sections"].as_u64()) {
            let n = n as usize;
            let next = sections.get(n).cloned();
            sections.truncate(n);
            if c.unwrap()["marker"] == true {
                sections.push(fc_ipfs::car::BOXO_MARKER.to_vec());
            } else if let Some(k) = c.unwrap()["end_inside"].as_u64() {
                sections.push(next.unwrap()[..k as usize].to_vec());
            }
        }
        if let (Some(n), Some(ins)) = (
            c.and_then(|c| c["after_sections"].as_u64()),
            c.and_then(|c| c.get("insert")),
        ) {
            sections.insert(n as usize, b64(&ins["base64"]));
        }
        for s in sections {
            body.extend_from_slice(&s);
        }
        stream(
            200,
            &format!("application/vnd.ipld.car; version=1; order=dfs; dups={dups}"),
            body,
        )
    }
}

fn stream(status: u16, content_type: &str, body: Vec<u8>) -> Answer {
    Answer::Stream {
        status,
        headers: vec![("content-type".to_owned(), content_type.to_owned())],
        body,
        stall_after: None,
    }
}

fn plan(root: Root, path: &str, headers: Vec<(String, String)>) -> Verify {
    let backend = Backend::ipfs(Ipfs::Gateway, true);
    Verify {
        node: Node::Ipfs,
        root,
        path: path.to_owned(),
        query: String::new(),
        headers,
        retry: retry(backend),
        timers: timers(backend),
        response: vec![ResponseOp::StripPageState],
        trust: Trust {
            name: None,
            content: ContentTrust::Verified,
        },
    }
}

fn opts(car: bool, now: i64) -> Opts {
    Opts {
        car,
        now,
        ..Opts::default()
    }
}

/// A path as an HTTP client sends it: WHATWG's path percent-encode set.
fn normalized(path: &str) -> String {
    let mut out = String::new();
    for &b in path.as_bytes() {
        if !(0x20..0x7f).contains(&b) || b" \"#<>?`{}^".contains(&b) {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(char::from(b));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The world, held to Kubo.

/// The honest gateway's CARs and raw blocks are Kubo's, for every request
/// Kubo answered in dweb-verify.json: the same blocks, in the same order.
#[test]
fn the_gateway_answers_as_kubo_did() {
    let doc = load("dweb-verify.json");
    let blocks = Blocks::new(&doc);
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    let mut n = 0;
    for e in doc["ipfs"]["kubo"].as_array().unwrap() {
        let r = &e["response"];
        let Some(car) = r["body"].get("car") else {
            continue;
        };
        if r["status"] != 200 || car["complete"] != true {
            continue;
        }
        // Only the requests the core makes: duplicates sent.
        let accept = pairs(&e["request"]["headers"]);
        if !accept
            .iter()
            .any(|(n, v)| n == "accept" && v.ends_with("dups=y"))
        {
            continue;
        }
        let path = e["request"]["path"].as_str().unwrap();
        let req = PieceRequest {
            id: fc_dweb::verifier::PieceId(0),
            path: path.to_owned(),
            headers: vec![(
                "accept".to_owned(),
                "application/vnd.ipld.car; version=1; order=dfs; dups=y".to_owned(),
            )],
            stream: true,
            max_bytes: None,
        };
        let Answer::Stream { body, .. } = common::World::answer(&world, &req) else {
            panic!()
        };
        // Read the sections back.
        let mut reader = fc_ipfs::car::Reader::new();
        let pushed = reader.push(&body);
        assert!(pushed.error.is_none(), "{}", e["id"]);
        let got: Vec<Key> = pushed.sections.iter().map(|s| key(s.cid())).collect();
        let want: Vec<Key> = car["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| key(&cid_bytes(c.as_str().unwrap())))
            .collect();
        assert_eq!(got, want, "{}", e["id"]);
        n += 1;
    }
    assert!(n > 150, "{n}");
}

// ---------------------------------------------------------------------------
// The native exchanges.

/// How the core's answer to a native exchange differs from GatewayCore's,
/// by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Same,
    /// A percent-encoded name the native node doesn't decode
    /// (`ipfs-path-decoding`): the core finds it.
    Decoded,
    /// An RSA key the native reader re-encodes or takes under 2,048 bits
    /// (`rsa-keys`).
    RsaKeys,
    /// A record that names a DNSLink name: no fallback.
    Dnslink,
}

#[test]
fn native_exchanges_through_cars() {
    replay_native(true);
}

/// The same, from a gateway the probe found without ordered CARs: every
/// block raw.
#[test]
fn native_exchanges_through_raw_blocks() {
    replay_native(false);
}

fn replay_native(car: bool) {
    let doc = load("dweb-verify.json");
    let blocks = Blocks::new(&doc);
    let now = doc["meta"]["clock_unix"].as_i64().unwrap();
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    let exchanges = doc["ipfs"]["native"].as_array().unwrap();
    // A percent-encoded name's twin: the same request unencoded, which the
    // native node answers (deviation ipfs-path-decoding).
    let twin = |e: &Json| {
        let norm = |x: &Json| normalized(x["request"]["path"].as_str().unwrap());
        exchanges.iter().find(|x| {
            x["case"] == e["case"]
                && x["request"]["method"] == e["request"]["method"]
                && x["request"]["headers"] == e["request"]["headers"]
                && norm(x) == norm(e)
                && x["response"]["status"] != 404
        })
    };
    let mut kinds: BTreeMap<Kind, usize> = BTreeMap::new();
    let mut unplanned = Vec::new();
    for e in exchanges {
        let id = e["id"].as_str().unwrap();
        let req = &e["request"];
        let full = req["path"].as_str().unwrap();
        let (ns, rest) = full[1..].split_once('/').unwrap();
        let (target, below) = rest.split_once('/').map_or((rest, ""), |(t, b)| (t, b));
        let below = if rest.contains('/') {
            format!("/{below}")
        } else {
            String::new()
        };
        let root = if ns == "ipfs" {
            Root::Ipfs(canonical(target))
        } else {
            Root::Ipns(target.to_owned())
        };
        // A tag the page holds is the core's: the CIDv0's, as the core
        // names the root, in CIDv1.
        let headers: Vec<(String, String)> = pairs(&req["headers"])
            .into_iter()
            .filter(|(n, _)| n == "range" || n == "if-none-match")
            .map(|(n, v)| {
                if ns == "ipfs" && target.starts_with("Qm") {
                    (n, v.replace(target, &canonical(target)))
                } else {
                    (n, v)
                }
            })
            .collect();
        let method = if req["method"] == "HEAD" {
            Method::Head
        } else {
            Method::Get
        };
        let p = plan(root, &normalized(&below), headers);
        if fc_dweb::verifier::Verifier::new(1, &p, method, None, false, Default::default()).is_err()
        {
            unplanned.push(id.to_owned());
            continue;
        }
        let got = run(id, &p, method, &world, opts(car, now));
        // A page that names the root (a listing, an error) names the core's:
        // the CIDv0 in CIDv1, and its length follows.
        let swap = |s: &str| {
            if target.starts_with("Qm") && ns == "ipfs" {
                s.replace(target, &canonical(target))
            } else {
                s.to_owned()
            }
        };
        let expected = |r: &Json| {
            let mut body = body_of(&r["body"]);
            let mut swapped = false;
            if let Expected::Bytes(b) = &body
                && let Ok(text) = std::str::from_utf8(b)
                && swap(text) != text
            {
                body = Expected::Bytes(swap(text).into_bytes());
                swapped = true;
            }
            let mut headers: Vec<(String, String)> = pairs(&r["headers"])
                .into_iter()
                .map(|(n, v)| (n, swap(&v)))
                .collect();
            if let (Expected::Bytes(b), true) = (&body, swapped) {
                for h in &mut headers {
                    if h.0 == "content-length" {
                        h.1 = b.len().to_string();
                    }
                }
            }
            (headers, body)
        };
        let kind = if e["case"].as_str().unwrap().contains("rsa-2041") {
            Kind::RsaKeys
        } else if ns == "ipns"
            && blocks
                .values
                .get(target)
                .is_some_and(|v| v.starts_with("/ipns/") && !v[6..].starts_with('k'))
        {
            // The record names a DNSLink name.
            Kind::Dnslink
        } else if below.contains('%') && e["response"]["status"] == 404 {
            Kind::Decoded
        } else {
            Kind::Same
        };
        *kinds.entry(kind).or_default() += 1;
        match kind {
            Kind::Same => {
                let r = &e["response"];
                let head = got
                    .head
                    .as_ref()
                    .unwrap_or_else(|| panic!("{id}: {:?}", got.ending));
                let (want, want_body) = expected(r);
                assert_eq!(
                    head.status,
                    r["status"].as_u64().unwrap() as u16,
                    "{id}: {:?}",
                    got.ending
                );
                assert_eq!(head.headers, want, "{id}");
                if method == Method::Get && head.status != 304 {
                    assert_eq!(got.ending, Some(Ending::End), "{id}");
                    check_body(id, &got.body, &want_body);
                }
                let label = if ns == "ipns" {
                    ContentTrust::LatestAsserted
                } else {
                    ContentTrust::Verified
                };
                assert_eq!(head.trust.content, label, "{id}");
            }
            Kind::Decoded => {
                let head = got
                    .head
                    .as_ref()
                    .unwrap_or_else(|| panic!("{id}: {:?}", got.ending));
                match twin(e) {
                    Some(t) => {
                        let r = &t["response"];
                        let (want, want_body) = expected(r);
                        assert_eq!(head.status, r["status"].as_u64().unwrap() as u16, "{id}");
                        assert_eq!(head.headers, want, "{id}");
                        if method == Method::Get {
                            check_body(id, &got.body, &want_body);
                        }
                    }
                    // No unencoded twin (a name holding `&`, `<` and `>`):
                    // found, as the decoded name is.
                    None => assert_eq!(head.status, 200, "{id}"),
                }
            }
            Kind::RsaKeys => {
                assert_eq!(
                    got.ending,
                    Some(Ending::Error(
                        502,
                        fc_dweb::verifier::IPFS_VERIFICATION_FAILED.to_owned()
                    )),
                    "{id}"
                );
            }
            Kind::Dnslink => {
                assert_eq!(
                    got.ending,
                    Some(Ending::Error(
                        502,
                        fc_dweb::verifier::IPFS_UNVERIFIABLE.to_owned()
                    )),
                    "{id}"
                );
            }
        }
    }
    // A `..` segment, plain or percent-encoded: main's validation refuses
    // it, as the native node does.
    for id in &unplanned {
        let e = exchanges.iter().find(|e| e["id"] == id.as_str()).unwrap();
        let path = e["request"]["path"].as_str().unwrap().to_ascii_lowercase();
        assert!(path.replace("%2e", ".").contains("/../"), "{id}");
        assert_eq!(e["response"]["status"], 400, "{id}");
    }
    assert_eq!(unplanned.len(), 4, "{unplanned:?}");
    assert_eq!(kinds[&Kind::Same], 474, "{kinds:?}");
    assert_eq!(kinds[&Kind::Decoded], 14, "{kinds:?}");
    assert_eq!(kinds[&Kind::RsaKeys], 4, "{kinds:?}");
    assert_eq!(kinds[&Kind::Dnslink], 4, "{kinds:?}");
}

/// A body as the vectors write it.
fn body_of(b: &Json) -> Expected {
    if let Some(c) = b.get("content") {
        let seed = c["seed"].as_str().unwrap();
        let from = c["from"].as_u64().unwrap() as usize;
        let n = c["length"].as_u64().unwrap() as usize;
        return Expected::Bytes(content(seed, from + n)[from..].to_vec());
    }
    if let Some(x) = b.get("base64") {
        return Expected::Bytes(b64(x));
    }
    if let Some(h) = b.get("sha256") {
        return Expected::Digest(
            b["length"].as_u64().unwrap() as usize,
            h.as_str().unwrap().to_owned(),
        );
    }
    Expected::Bytes(vec![])
}

// ---------------------------------------------------------------------------
// The request cases.

fn check_case(blocks: &Blocks, id: &str, c: &Json, order: Order) {
    let p = &c["plan"];
    let root = if let Some(r) = p["root"]["ipfs"].as_str() {
        Root::Ipfs(r.to_owned())
    } else {
        Root::Ipns(p["root"]["ipns"].as_str().unwrap().to_owned())
    };
    let plan = plan(root, p["path"].as_str().unwrap(), pairs(&p["headers"]));
    let method = if c["method"] == "HEAD" {
        Method::Head
    } else {
        Method::Get
    };
    // The case's own blocks, which the gateway holds beside the vectors'.
    let mut own = None;
    if let Some(extra) = c["world"]["blocks"].as_object() {
        let mut b = blocks.clone();
        for (cid, block) in extra {
            b.blocks.insert(key(&cid_bytes(cid)), b64(&block["base64"]));
        }
        own = Some(b);
    }
    let world = Gateway {
        blocks: own.as_ref().unwrap_or(blocks),
        changes: c["world"]["changes"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
    };
    let car = c["world"]["gateway"]["car"].as_bool().unwrap_or(true);
    let mut o = opts(car, load_now());
    o.order = order;
    let got = run(id, &plan, method, &world, o);
    let x = &c["expect"];
    if let Some(err) = x.get("error") {
        let status = err["status"].as_u64().unwrap() as u16;
        let message = err["body"]["message"].as_str().unwrap().to_owned();
        assert_eq!(got.ending, Some(Ending::Error(status, message)), "{id}");
        return;
    }
    let h = &x["head"];
    let head = got
        .head
        .as_ref()
        .unwrap_or_else(|| panic!("{id}: no head: {:?}", got.ending));
    assert_eq!(head.status, h["status"].as_u64().unwrap() as u16, "{id}");
    assert_eq!(head.headers, pairs(&h["headers"]), "{id}");
    assert_eq!(
        head.trust.content.as_str(),
        h["trust"]["content"].as_str().unwrap(),
        "{id}"
    );
    if let Some(t) = x.get("truncated") {
        check_body(id, &got.body, &body_of(&t["released"]));
        let a = &t["abort"];
        assert_eq!(
            got.ending,
            Some(Ending::Abort(
                a["code"].as_str().unwrap().to_owned(),
                a["message"].as_str().unwrap().to_owned()
            )),
            "{id}"
        );
    } else {
        check_body(id, &got.body, &body_of(&x["body"]));
    }
}

fn load_now() -> i64 {
    load("dweb-verify.json")["meta"]["clock_unix"]
        .as_i64()
        .unwrap()
}

#[test]
fn every_ipfs_request_case() {
    let doc = load("dweb-verify.json");
    let blocks = Blocks::new(&doc);
    let mut n = 0;
    for c in load("dweb-verify-cases.json")["requests"]
        .as_array()
        .unwrap()
    {
        let id = c["id"].as_str().unwrap();
        if !(id.starts_with("ipfs/") || id.starts_with("ipns/")) || id == "ipns/floor" {
            continue;
        }
        check_case(&blocks, id, c, Order::Fifo);
        check_case(&blocks, id, c, Order::Lifo);
        n += 1;
    }
    assert_eq!(n, 38, "{n}");
}

// ---------------------------------------------------------------------------
// The machine: budgets, cancels, a slow page, an abort.

const SITE: &str = "bafybeiguwjmddvr4iiah6ekgvrovb5zfb6eg5c6loikxvxlxzlwea5dabm";
const HAMT: &str = "bafybeici5ieuuuekpr6eknkq2dkfgj4oxoqe5bnwp5hgs7xvdvllmbydca";
/// 10 MiB in 40 raw leaves of 256 KiB under one node.
const FILE_10M: &str = "bafybeicts2tssv6avpna26sql26mlrowdhxwjpskl35ibnxdf7tf7cgo5a";
const FILE_10M_SEED: &str = "ipfs-file-10485760";
const LEAF: usize = 262_144;

fn ranged(root: &str, path: &str, range: Option<&str>) -> Verify {
    let headers = range
        .map(|r| vec![("range".to_owned(), r.to_owned())])
        .unwrap_or_default();
    plan(Root::Ipfs(root.to_owned()), path, headers)
}

/// The big file's `n`th leaf.
fn leaf(blocks: &Blocks, n: usize) -> String {
    let root = blocks.get(&cid_bytes(FILE_10M)).unwrap();
    let (cid, _, _) = &links(&root)[n];
    ipfs_cid::to_text(&ipfs_cid::parse(cid).unwrap())
}

/// Every reservation short of what the walk needs, through CARs and raw
/// blocks: each request either answers as it does with room, or is
/// `unverifiable`, and never holds past its budget (the driver checks
/// that at every step).
#[test]
fn budgets_exhausted_at_each_reservation() {
    let blocks = Blocks::new(&load("dweb-verify.json"));
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    let window = fc_dweb::verifier::STREAM_WINDOW;
    let car_room = fc_ipfs::car::MAX_SECTION + fc_ipfs::car::MAX_HEADER;
    let plans = [
        ranged(SITE, "/style.css", None),
        ranged(SITE, "/", None),
        ranged(HAMT, "/", None),
        ranged(FILE_10M, "/", Some("bytes=300000-600000")),
    ];
    for p in &plans {
        for car in [true, false] {
            let o = opts(car, 0);
            let honest = run("budget", p, Method::Get, &world, o);
            assert_eq!(honest.ending, Some(Ending::End), "{:?} {}", p.root, p.path);
            let (mut ended, mut refused) = (0, 0);
            for budget in [
                0,
                100,
                3000,
                64 << 10,
                window,
                window + LEAF,
                window + car_room - 1,
                window + car_room,
                2 * window + car_room,
                3 << 20,
                4 << 20,
                6 << 20,
            ] {
                let label = format!("budget {budget} {} car={car}", p.path);
                let got = run(&label, p, Method::Get, &world, Opts { budget, ..o });
                match &got.ending {
                    Some(Ending::End) => {
                        assert_eq!(got.body, honest.body, "{budget}");
                        assert_eq!(got.head, honest.head, "{budget}");
                        ended += 1;
                    }
                    Some(Ending::Error(502, m)) | Some(Ending::Abort(_, m)) => {
                        assert_eq!(m, fc_dweb::verifier::IPFS_UNVERIFIABLE, "{budget}");
                        refused += 1;
                    }
                    other => panic!("{budget}: {other:?}"),
                }
            }
            // Room enough answers.
            assert!(ended > 0 && refused > 0, "{:?} {} {car}", p.root, p.path);
        }
    }
}

/// A cancel at every step, through CARs and raw blocks: before the head
/// `cancelled`, after it an abort, with only verified bytes released.
#[test]
fn cancel_at_every_step() {
    let blocks = Blocks::new(&load("dweb-verify.json"));
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    let want = content(FILE_10M_SEED, 10 << 20);
    let p = ranged(FILE_10M, "/", Some("bytes=100-600000"));
    for car in [true, false] {
        let honest = run("cancel", &p, Method::Get, &world, opts(car, 0));
        assert_eq!(honest.body, want[100..=600_000]);
        let mut seen = [0usize; 3];
        for at in 1..160 {
            let got = run(
                "cancel",
                &p,
                Method::Get,
                &world,
                Opts {
                    cancel_after: Some(at),
                    ..opts(car, 0)
                },
            );
            match got.ending {
                Some(Ending::Cancelled) => {
                    assert!(got.head.is_none());
                    seen[0] += 1;
                }
                Some(Ending::Abort(ref code, _)) => {
                    assert_eq!(code, "cancelled");
                    assert!(got.head.is_some());
                    seen[1] += 1;
                }
                Some(Ending::End) => seen[2] += 1,
                ref other => panic!("{at}: {other:?}"),
            }
            assert!(
                want[100..].starts_with(&got.body),
                "{at}: a prefix of the right bytes"
            );
        }
        assert!(seen.iter().all(|&n| n > 0), "{car}: {seen:?}");
    }
}

/// A page that reads slowly holds the gateway back: the CAR is read no
/// further while verified body waits for the page, so what the machine
/// holds stays far below the file.
#[test]
fn a_slow_page_backpressures_the_gateway() {
    let blocks = Blocks::new(&load("dweb-verify.json"));
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    let want = content(FILE_10M_SEED, 10 << 20);
    let p = ranged(FILE_10M, "/", None);
    for car in [true, false] {
        let got = run(
            "slow",
            &p,
            Method::Get,
            &world,
            Opts {
                page: Some(16 << 10),
                ..opts(car, 0)
            },
        );
        assert_eq!(got.ending, Some(Ending::End));
        assert!(got.body == want, "{car}");
        let streams = got.pieces.iter().filter(|r| r.stream).count();
        if car {
            assert_eq!(streams, 1);
        } else {
            // The root and its 40 leaves, raw.
            assert_eq!(streams, 41);
        }
        // The CAR's window, its reader's room and the sections hashing, or
        // eight raw blocks in flight; and the body the page hasn't read:
        // under 4 MiB, where an unbounded walk would fill its 8 MiB.
        assert!(got.peak < 4 << 20, "{car}: {}", got.peak);
    }
}

/// A leaf that fails its hash after the head: the bytes before it are
/// released, then the request aborts, with a slow page so verified bytes
/// wait in the machine. Through the CAR (a section flipped) and raw (the
/// wrong block sent).
#[test]
fn a_bad_leaf_after_the_head_aborts() {
    let blocks = Blocks::new(&load("dweb-verify.json"));
    let want = content(FILE_10M_SEED, 10 << 20);
    let bad = leaf(&blocks, 5);
    let p = ranged(FILE_10M, "/", None);
    for car in [true, false] {
        let change = if car {
            serde_json::json!({"piece": "car", "flip": {"cid": bad, "offset": 1000}})
        } else {
            serde_json::json!({"piece": "raw", "cid": bad, "as": leaf(&blocks, 6)})
        };
        let world = Gateway {
            blocks: &blocks,
            changes: vec![change],
        };
        let got = run(
            "abort",
            &p,
            Method::Get,
            &world,
            Opts {
                page: Some(4096),
                ..opts(car, 0)
            },
        );
        assert_eq!(
            got.ending,
            Some(Ending::Abort(
                "verification_failed".to_owned(),
                fc_dweb::verifier::IPFS_VERIFICATION_FAILED.to_owned()
            )),
            "{car}"
        );
        assert!(got.body == want[..5 * LEAF], "{car}: {}", got.body.len());
    }
}

/// A HEAD reads the file's root and the bytes its type is sniffed from,
/// no more, and has no body.
#[test]
fn head_reads_only_to_the_sniff() {
    let blocks = Blocks::new(&load("dweb-verify.json"));
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    let p = ranged(FILE_10M, "/", None);
    let got = run("head", &p, Method::Head, &world, opts(true, 0));
    let head = got.head.as_ref().unwrap();
    assert!(!head.body);
    assert!(got.body.is_empty());
    let paths: Vec<&str> = got.pieces.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [format!(
            "/ipfs/{FILE_10M}?format=car&dag-scope=entity&entity-bytes=0:512"
        )]
    );
    let got = run("head", &p, Method::Head, &world, opts(false, 0));
    assert!(got.body.is_empty());
    let paths: Vec<String> = got.pieces.iter().map(|r| r.path.clone()).collect();
    assert_eq!(
        paths,
        [
            format!("/ipfs/{FILE_10M}?format=raw"),
            format!("/ipfs/{}?format=raw", leaf(&blocks, 0)),
        ]
    );
    assert_eq!(
        got.head,
        run("head", &p, Method::Head, &world, opts(true, 0)).head
    );
}

// ---------------------------------------------------------------------------
// Files built here: sizes that disagree, a block past its room.

/// A CIDv1 for `block`: `codec`, and SHA2-256 or the identity hash.
fn cid_of(codec: u8, block: &[u8], identity: bool) -> Vec<u8> {
    use sha2::Digest;
    let mut out = vec![0x01, codec];
    if identity {
        out.push(0x00);
        varint(block.len() as u64, &mut out);
        out.extend_from_slice(block);
    } else {
        out.extend_from_slice(&[0x12, 0x20]);
        out.extend_from_slice(&sha2::Sha256::digest(block));
    }
    out
}

fn raw_cid(block: &[u8]) -> Vec<u8> {
    cid_of(0x55, block, false)
}

/// A UnixFS file node in canonical dag-pb: its links (CID, Tsize), then
/// `Data { Type: File, filesize, blocksizes }`.
fn file_node(links: &[(&[u8], u64)], filesize: u64, blocksizes: &[u64]) -> Vec<u8> {
    let mut data = vec![0x08, 0x02, 0x18];
    varint(filesize, &mut data);
    for b in blocksizes {
        data.push(0x20);
        varint(*b, &mut data);
    }
    let mut out = Vec::new();
    for (cid, tsize) in links {
        let mut l = vec![0x0a];
        varint(cid.len() as u64, &mut l);
        l.extend_from_slice(cid);
        l.extend_from_slice(&[0x12, 0x00, 0x18]);
        varint(*tsize, &mut l);
        out.push(0x12);
        varint(l.len() as u64, &mut out);
        out.extend_from_slice(&l);
    }
    out.push(0x0a);
    varint(data.len() as u64, &mut out);
    out.extend_from_slice(&data);
    out
}

fn text(cid: &[u8]) -> String {
    ipfs_cid::to_text(&ipfs_cid::parse(cid).unwrap())
}

/// A file whose child disagrees with its `blocksizes` entry (deviation
/// `unixfs-sizes`): a raw leaf longer than its entry, and a node whose
/// `filesize` isn't its entry. The bytes before it are released, then the
/// body is cut as malformed, through the CAR and raw.
#[test]
fn sizes_that_disagree_cut_the_body_as_malformed() {
    let mut blocks = Blocks::new(&load("dweb-verify.json"));
    let a = content("sizes-a", 1000);
    let b = content("sizes-b", 1000);
    let (la, lb) = (raw_cid(&a), raw_cid(&b));
    // The second leaf's entry says 999.
    let leaf_root = file_node(&[(&la, 1000), (&lb, 1000)], 1999, &[1000, 999]);
    // The second child, a node of 999 bytes where its entry says 1000.
    let inner = file_node(&[(&lb, 1000)], 999, &[999]);
    let li = cid_of(0x70, &inner, false);
    let node_root = file_node(&[(&la, 1000), (&li, 1100)], 2000, &[1000, 1000]);
    let roots = [
        cid_of(0x70, &leaf_root, false),
        cid_of(0x70, &node_root, false),
    ];
    for (cid, block) in [
        (&la, &a),
        (&lb, &b),
        (&li, &inner),
        (&roots[0], &leaf_root),
        (&roots[1], &node_root),
    ] {
        blocks.blocks.insert(key(cid), block.clone());
    }
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    for root in &roots {
        for car in [true, false] {
            let p = ranged(&text(root), "/", None);
            let got = run("sizes", &p, Method::Get, &world, opts(car, 0));
            assert_eq!(got.head.as_ref().map(|h| h.status), Some(200), "{car}");
            assert_eq!(
                got.ending,
                Some(Ending::Abort(
                    "malformed".to_owned(),
                    fc_dweb::verifier::IPFS_MALFORMED.to_owned()
                )),
                "{car}"
            );
            assert_eq!(got.body, a, "{car}");
        }
    }
}

/// A raw block longer than the room it was reserved at (a raw leaf at its
/// entry): its bytes past that room need room of their own, and a request
/// without it is `unverifiable` rather than past its budget. With room, the
/// block fails its hash. The file's root is an identity CID, so the leaf's
/// room is all the walk reserves.
#[test]
fn a_raw_block_past_its_room() {
    let mut blocks = Blocks::new(&load("dweb-verify.json"));
    let x = b"x".to_vec();
    let lx = raw_cid(&x);
    let root = cid_of(0x70, &file_node(&[(&lx, 1)], 1, &[1]), true);
    blocks.blocks.insert(key(&lx), x);
    // Its answer: a 256 KiB leaf of the vectors'.
    let world = Gateway {
        blocks: &blocks,
        changes: vec![serde_json::json!({
            "piece": "raw",
            "cid": text(&lx),
            "as": "bafkreicnlcfal2ime6l6narxom5xnnhezrdhgtg5etwkkq65kwtj4lt5xa",
        })],
    };
    let p = ranged(&text(&root), "/", None);
    let window = fc_dweb::verifier::STREAM_WINDOW;
    for (budget, message) in [
        (window + 1024, fc_dweb::verifier::IPFS_UNVERIFIABLE),
        (
            window + (1 << 20),
            fc_dweb::verifier::IPFS_VERIFICATION_FAILED,
        ),
    ] {
        let got = run(
            "past its room",
            &p,
            Method::Get,
            &world,
            Opts {
                budget,
                ..opts(false, 0)
            },
        );
        assert_eq!(
            got.ending,
            Some(Ending::Error(502, message.to_owned())),
            "{budget}"
        );
    }
}

/// An Ed25519 IPNS name from a seed, and its signer.
fn ipns_key(seed: u8) -> (ed25519_dalek::SigningKey, String) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut name = vec![0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    name.extend_from_slice(key.verifying_key().as_bytes());
    (key, text(&name))
}

fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// A V2-only record naming `value`, valid until 2099, its signed data in
/// DAG-CBOR's canonical key order.
fn ipns_record(key: &ed25519_dalek::SigningKey, value: &str) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut data = Vec::new();
    cbor_head(5, 5, &mut data);
    let field = |k: &str, data: &mut Vec<u8>| {
        cbor_head(3, k.len() as u64, data);
        data.extend_from_slice(k.as_bytes());
    };
    field("TTL", &mut data);
    cbor_head(0, 60_000_000_000, &mut data);
    field("Value", &mut data);
    cbor_head(2, value.len() as u64, &mut data);
    data.extend_from_slice(value.as_bytes());
    field("Sequence", &mut data);
    cbor_head(0, 1, &mut data);
    field("Validity", &mut data);
    let eol = b"2099-01-01T00:00:00Z";
    cbor_head(2, eol.len() as u64, &mut data);
    data.extend_from_slice(eol);
    field("ValidityType", &mut data);
    cbor_head(0, 0, &mut data);
    let mut message = b"ipns-signature:".to_vec();
    message.extend_from_slice(&data);
    let mut out = vec![0x42, 64];
    out.extend_from_slice(&key.sign(&message).to_bytes());
    out.push(0x4a);
    varint(data.len() as u64, &mut out);
    out.extend_from_slice(&data);
    out
}

/// Names that name names: `GatewayCore` follows three, resolves a fourth
/// and answers 400 whatever it names, and asks for no fifth. So does the
/// core, its records verified.
#[test]
fn a_fourth_record_is_refused_whatever_it_names() {
    let mut blocks = Blocks::new(&load("dweb-verify.json"));
    let style = "/ipfs/bafkreiaeicvgt6kx3ml6fw6t6r2gkenzrn2zajqbxm3dp2mgpbyl2ibnye";
    let mut first = Vec::new();
    for n in 1..=5u8 {
        let keys: Vec<_> = (0..n).map(|i| ipns_key(n * 16 + i)).collect();
        for (i, (key, name)) in keys.iter().enumerate() {
            let value = match keys.get(i + 1) {
                Some((_, next)) => format!("/ipns/{next}"),
                None => style.to_owned(),
            };
            blocks
                .records
                .insert(name.clone(), ipns_record(key, &value));
        }
        first.push(keys[0].1.clone());
    }
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    for (n, name) in (1..=5).zip(&first) {
        let p = plan(Root::Ipns(name.clone()), "", vec![]);
        let got = run("chain", &p, Method::Get, &world, opts(true, 0));
        let records = got
            .pieces
            .iter()
            .filter(|r| r.path.starts_with("/ipns/"))
            .count();
        assert_eq!(records, n.min(4), "{n}");
        assert_eq!(got.ending, Some(Ending::End), "{n}");
        let head = got.head.as_ref().unwrap();
        if n <= 3 {
            assert_eq!(head.status, 200, "{n}");
            assert_eq!(head.trust.content, ContentTrust::LatestAsserted);
            assert_eq!(got.body, content("ipfs-site-style", 3000), "{n}");
        } else {
            assert_eq!(head.status, 400, "{n}");
            let body = String::from_utf8(got.body.clone()).unwrap();
            assert!(body.contains("dnslink recursion limit exceeded"), "{body}");
        }
    }
}

// ---------------------------------------------------------------------------
// Review round 1: the sniff's window, record-value paths, the page's hold.

fn header_of<'h>(head: &'h fc_dweb::verifier::Head, name: &str) -> Option<&'h str> {
    head.headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// The type is sniffed from bytes 0 to 512 only, as `GatewayCore` reads
/// them: `<html` ending at byte 512 is HTML, one byte later it isn't, and a
/// range ending sooner sniffs only its own bytes. Each expectation is
/// `GatewayCore`'s own answer over the same blocks, through CARs and raw
/// blocks, for a raw block and for a file whose marker is in its second
/// leaf.
#[test]
fn the_type_is_sniffed_from_bytes_0_to_512() {
    const HTML: &str = "text/html";
    const BIN: &str = "application/octet-stream";
    let mut blocks = Blocks::new(&load("dweb-verify.json"));
    let mut roots = Vec::new();
    for spaces in [507usize, 508, 509, 600] {
        let mut body = vec![b' '; spaces];
        body.extend_from_slice(b"<html>");
        body.resize(1000, b'x');
        let leaf = raw_cid(&body);
        blocks.blocks.insert(key(&leaf), body.clone());
        let (l1, l2) = (raw_cid(&body[..300]), raw_cid(&body[300..]));
        blocks.blocks.insert(key(&l1), body[..300].to_vec());
        blocks.blocks.insert(key(&l2), body[300..].to_vec());
        let node = file_node(&[(&l1, 300), (&l2, 700)], 1000, &[300, 700]);
        let file = cid_of(0x70, &node, false);
        blocks.blocks.insert(key(&file), node);
        roots.push((spaces, body, leaf, file));
    }
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    for (spaces, body, leaf, file) in &roots {
        let html = *spaces <= 508;
        let cases: [(Method, Option<&str>, &str); 6] = [
            (Method::Get, None, if html { HTML } else { BIN }),
            (Method::Head, None, if html { HTML } else { BIN }),
            (Method::Get, Some("bytes=0-510"), BIN),
            (
                Method::Get,
                Some("bytes=0-511"),
                if *spaces <= 507 { HTML } else { BIN },
            ),
            (
                Method::Get,
                Some("bytes=0-700"),
                if html { HTML } else { BIN },
            ),
            (Method::Get, Some("bytes=5-700"), BIN),
        ];
        for (method, range, want) in cases {
            for root in [leaf, file] {
                for car in [true, false] {
                    let p = ranged(&text(root), "", range);
                    let label = format!("{spaces} {method:?} {range:?} car={car}");
                    let got = run(&label, &p, method, &world, opts(car, 0));
                    let head = got.head.as_ref().unwrap_or_else(|| panic!("{label}"));
                    assert_eq!(header_of(head, "content-type"), Some(want), "{label}");
                    let (a, b) = match range {
                        None => (0, 999),
                        Some(r) => {
                            let (a, b) = r[6..].split_once('-').unwrap();
                            (a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap())
                        }
                    };
                    if method == Method::Get {
                        assert_eq!(got.ending, Some(Ending::End), "{label}");
                        assert!(got.body == body[a..=b], "{label}");
                    } else {
                        assert!(got.body.is_empty(), "{label}");
                    }
                }
            }
        }
    }
}

/// A record's value path as `GatewayCore` reads it: its segments matched
/// as written (an encoded name isn't decoded, so isn't found), a `.` or
/// `..`, written or percent-encoded, refused with the 400 before anything
/// else is asked, in a value naming another name too; and the value's
/// segments and the request's together at most 256, across every record.
/// Each expectation is `GatewayCore`'s own answer over the same blocks and
/// records, but past 256 segments, which is the core's bound alone.
#[test]
fn record_values_are_paths_as_gatewaycore_reads_them() {
    let mut blocks = Blocks::new(&load("dweb-verify.json"));
    let style = content("ipfs-site-docs-page", 1200);
    let traversal = "path traversal segments are not allowed";
    // (value suffix after /ipfs/<site>, request path, expectation).
    enum Want {
        Page(u16, &'static str),
        Body(Vec<u8>),
        Unverifiable,
    }
    let deep = |n: usize| "/a".repeat(n);
    let cases: Vec<(String, &str, Want)> = vec![
        ("/..".into(), "/", Want::Page(400, traversal)),
        ("/docs/..".into(), "/", Want::Page(400, traversal)),
        ("/%2e%2e".into(), "/", Want::Page(400, traversal)),
        ("/docs/%2E%2e".into(), "/", Want::Page(400, traversal)),
        ("/.".into(), "/", Want::Page(400, traversal)),
        ("/./index.html".into(), "/", Want::Page(400, traversal)),
        ("/docs/page.html".into(), "/", Want::Body(style.clone())),
        ("//docs//page.html".into(), "/", Want::Body(style.clone())),
        ("/docs".into(), "/page.html", Want::Body(style.clone())),
        (
            "/docs%2fpage.html".into(),
            "/",
            Want::Page(404, "not found"),
        ),
        (
            "/%C3%BCn%C3%AF/%C3%A7%C3%B8d%C3%A9.txt".into(),
            "/",
            Want::Page(404, "not found"),
        ),
        ("/%2e%2".into(), "/", Want::Page(404, "not found")),
        (deep(255), "/b", Want::Page(404, "not found")),
        (deep(256), "/b", Want::Unverifiable),
    ];
    let mut names = Vec::new();
    for (i, (suffix, _, _)) in cases.iter().enumerate() {
        let (key, name) = ipns_key(200 + i as u8);
        let value = format!("/ipfs/{SITE}{suffix}");
        blocks
            .records
            .insert(name.clone(), ipns_record(&key, &value));
        names.push(name);
    }
    // Across two records: a name whose value names another name.
    let chain = |seed: u8, first: &str, second: &str, blocks: &mut Blocks| {
        let (k1, n1) = ipns_key(seed);
        let (k2, n2) = ipns_key(seed + 1);
        blocks
            .records
            .insert(n1.clone(), ipns_record(&k1, &format!("/ipns/{n2}{first}")));
        blocks
            .records
            .insert(n2, ipns_record(&k2, &format!("/ipfs/{SITE}{second}")));
        n1
    };
    let up = chain(240, "/..", "/docs", &mut blocks);
    let fits = chain(242, &deep(200), &deep(56), &mut blocks);
    let over = chain(244, &deep(200), &deep(57), &mut blocks);
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    let check = |name: &str, path: &str, want: &Want, records: Option<usize>| {
        let p = plan(Root::Ipns(name.to_owned()), path, vec![]);
        let label = format!("{name} {path}");
        let got = run(&label, &p, Method::Get, &world, opts(true, 0));
        match want {
            Want::Page(status, detail) => {
                let head = got
                    .head
                    .as_ref()
                    .unwrap_or_else(|| panic!("{label}: {:?}", got.ending));
                assert_eq!(head.status, *status, "{label}");
                let body = String::from_utf8(got.body.clone()).unwrap();
                assert!(
                    body.contains(&format!("<p>{detail}</p>")),
                    "{label}: {body}"
                );
            }
            Want::Body(b) => {
                assert_eq!(got.ending, Some(Ending::End), "{label}");
                assert!(got.body == *b, "{label}");
            }
            Want::Unverifiable => assert_eq!(
                got.ending,
                Some(Ending::Error(
                    502,
                    fc_dweb::verifier::IPFS_UNVERIFIABLE.to_owned()
                )),
                "{label}"
            ),
        }
        if let Some(n) = records {
            let asked = got
                .pieces
                .iter()
                .filter(|r| r.path.starts_with("/ipns/"))
                .count();
            assert_eq!(asked, n, "{label}");
        }
    };
    for ((_, path, want), name) in cases.iter().zip(&names) {
        check(name, path, want, None);
    }
    // The `..` in the first value: refused before the second record.
    check(&up, "/", &Want::Page(400, traversal), Some(1));
    check(&fits, "/", &Want::Page(404, "not found"), Some(2));
    check(&over, "/", &Want::Unverifiable, Some(2));
}

/// The page holds raw blocks back counting what it hasn't read: the body
/// queued and what was sent without credit, up to and including 512 KiB.
/// A file of 13 raw leaves of 128 KiB, and a page that never reads: the
/// first 8 are asked at once, then one more after each of the first three
/// leaves goes out (128, 256 and 384 KiB unread), and none once 512 KiB
/// wait.
#[test]
fn raw_blocks_wait_once_512_kib_are_unread() {
    let mut blocks = Blocks::new(&load("dweb-verify.json"));
    let leaf = 128 << 10;
    let content = content("checks-unread", 13 * leaf);
    let mut links = Vec::new();
    for i in 0..13 {
        let part = &content[i * leaf..(i + 1) * leaf];
        let c = raw_cid(part);
        blocks.blocks.insert(key(&c), part.to_vec());
        links.push(c);
    }
    let refs: Vec<(&[u8], u64)> = links.iter().map(|c| (&c[..], leaf as u64)).collect();
    let node = file_node(&refs, 13 * leaf as u64, &[leaf as u64; 13]);
    let root = cid_of(0x70, &node, false);
    blocks.blocks.insert(key(&root), node);
    let world = Gateway {
        blocks: &blocks,
        changes: vec![],
    };
    let p = ranged(&text(&root), "", None);
    let got = run(
        "unread",
        &p,
        Method::Get,
        &world,
        Opts {
            page: Some(0),
            ..opts(false, 0)
        },
    );
    let leaves = got
        .pieces
        .iter()
        .filter(|r| r.path != format!("/ipfs/{}?format=raw", text(&root)))
        .count();
    assert_eq!(leaves, 11, "{:?}", got.ending);
    assert!(got.ending.is_none());
}
