//! fc-swarm's write side (design 0015, SWM-2) against
//! tests/data/write-side.json, the answers bee-js 13.2.0 and core-sdk 0.2.2
//! give (tests/gen/generate.js): trees, tar and SOC bodies, feeds and GSOC
//! signers, byte for byte. Beside them, the chunker is checked against Bee's
//! own references in vectors/dweb-verify.json, against the read side's tree
//! rules, and against a recursive statement of the tree over random sizes
//! and splits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::PathBuf;

use base64::Engine;
use fc_swarm::chunker::{Chunker, Root, root_of};
use fc_swarm::feed::{self, Update};
use fc_swarm::gsoc::{self, Miner, Step};
use fc_swarm::tar::{self, TarWriter};
use fc_swarm::{CHUNK_SIZE, soc, tree, verify};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn answers() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/write-side.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// content(seed, n): SHA-256(seed ‖ u64_be(i)), concatenated and cut.
fn content(seed: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0u64;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(i.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        i += 1;
    }
    out.truncate(n);
    out
}

fn data(spec: &Value) -> Vec<u8> {
    if let Some(text) = spec["utf8"].as_str() {
        return text.as_bytes().to_vec();
    }
    content(
        spec["seed"].as_str().unwrap(),
        spec["length"].as_u64().unwrap() as usize,
    )
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

fn b64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap())
        .unwrap()
}

fn cases<'a>(all: &'a Value, section: &str, kind: &str) -> Vec<&'a Value> {
    all[section]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| kind.is_empty() || c["kind"] == kind)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Owned {
    address: [u8; 32],
    span: u64,
    payload: Vec<u8>,
}

/// Streams `data` through the chunker in pieces of `piece` bytes: every
/// chunk it seals and its root.
fn stream(data: &[u8], piece: usize) -> (Vec<Owned>, Root) {
    let mut chunks = Vec::new();
    let mut sink = |c: fc_swarm::chunker::Sealed<'_>| {
        chunks.push(Owned {
            address: c.address,
            span: c.span,
            payload: c.payload.to_vec(),
        })
    };
    let mut chunker = Chunker::new();
    for part in data.chunks(piece.max(1)) {
        chunker.write(part, &mut sink).unwrap();
    }
    let root = chunker.finish(&mut sink);
    (chunks, root)
}

fn digest(chunks: &[Owned]) -> String {
    let mut sorted: Vec<&Owned> = chunks.iter().collect();
    sorted.sort_by_key(|c| c.address);
    let mut h = Sha256::new();
    for c in sorted {
        h.update(c.address);
        h.update(c.span.to_le_bytes());
        h.update(&c.payload);
    }
    hex::encode(h.finalize())
}

/// Reads the tree back from its root with the read side's rules
/// (`tree::intermediate`, `tree::is_leaf`), each chunk checked against its
/// address, and returns the data.
fn read_back(root: &Root, chunks: &HashMap<[u8; 32], Owned>) -> Vec<u8> {
    fn walk(
        address: &[u8; 32],
        len: u64,
        chunks: &HashMap<[u8; 32], Owned>,
        root: &Owned,
        out: &mut Vec<u8>,
    ) {
        let chunk = if *address == root.address {
            root
        } else {
            &chunks[address]
        };
        let span = chunk.span.to_le_bytes();
        assert_eq!(verify::address_of(&span, &chunk.payload), Some(*address));
        if tree::is_leaf(len) {
            assert_eq!(chunk.payload.len() as u64, len);
            out.extend_from_slice(&chunk.payload);
            return;
        }
        let view = verify::Chunk {
            span,
            payload: &chunk.payload,
        };
        let node = tree::intermediate(&view, len).unwrap();
        for i in 0..node.len() {
            let (child, child_len) = node.child(i).unwrap();
            walk(&child, child_len, chunks, root, out);
        }
    }
    let owned = Owned {
        address: root.address(),
        span: root.span(),
        payload: root.payload().to_vec(),
    };
    let mut out = Vec::new();
    walk(&root.address(), root.span(), chunks, &owned, &mut out);
    out
}

#[test]
fn trees() {
    let all = answers();
    let list = cases(&all, "trees", "");
    assert!(list.len() >= 18);
    for case in list {
        let id = case["id"].as_str().unwrap();
        let input = data(&case["data"]);
        for piece in [1000, 4096, 131_072, input.len()] {
            let (chunks, root) = stream(&input, piece);
            assert_eq!(hex::encode(root.address()), case["root"], "{id} ({piece})");
            assert_eq!(root.span(), case["span"].as_u64().unwrap(), "{id}");
            assert_eq!(hex::encode(root.payload()), case["payload"], "{id}");
            let mut all_chunks = chunks.clone();
            all_chunks.push(Owned {
                address: root.address(),
                span: root.span(),
                payload: root.payload().to_vec(),
            });
            assert_eq!(
                all_chunks.len() as u64,
                case["chunks"]["count"].as_u64().unwrap(),
                "{id}"
            );
            assert_eq!(digest(&all_chunks), case["chunks"]["sha256"], "{id}");
            let by_address: HashMap<_, _> = chunks.into_iter().map(|c| (c.address, c)).collect();
            assert_eq!(read_back(&root, &by_address), input, "{id}");
        }
        assert_eq!(root_of(&input).unwrap().address(), b32(&case["root"]));
    }
}

/// Bee's own trees, from design 0009's cross-check against Bee's pipeline
/// (vectors/dweb-verify.json): every file without erasure coding, Ant's
/// two lone-reference trees excepted, which have Bee-shaped twins
/// (`-bee`): 524,289 bytes, and 67,108,865, where a lone leaf is carried up
/// two levels.
#[test]
fn trees_match_bees_references() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/dweb-verify.json");
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut checked = Vec::new();
    for file in vectors["swarm"]["files"].as_array().unwrap() {
        if file["redundancy"] != 0 || file.get("lone_leaf_wrappers").is_some() {
            continue;
        }
        let size = file["size"].as_u64().unwrap() as usize;
        let input = content(file["seed"].as_str().unwrap(), size);
        let root = root_of(&input).unwrap();
        assert_eq!(hex::encode(root.address()), file["root"], "{}", file["id"]);
        checked.push(file["id"].as_str().unwrap().to_owned());
    }
    for id in [
        "file-524289-rs0-bee",
        "file-67108865-rs0-bee",
        "file-4097-rs0",
    ] {
        assert!(checked.iter().any(|c| c == id), "{id}: {checked:?}");
    }
}

/// The tree as a recursive rule: at most 4,096 bytes is a leaf; otherwise
/// the data splits into branches of the smallest 4,096 × 128^k bytes that
/// leaves at most 128 of them, each its own tree, so a short last branch
/// sits at its own height, unwrapped.
fn model(data: &[u8]) -> [u8; 32] {
    let span = (data.len() as u64).to_le_bytes();
    if data.len() <= CHUNK_SIZE {
        return verify::address_of(&span, data).unwrap();
    }
    let mut branch = CHUNK_SIZE;
    while data.len().div_ceil(branch) > tree::MAX_REFS {
        branch *= tree::MAX_REFS;
    }
    let refs: Vec<u8> = data.chunks(branch).flat_map(model).collect();
    verify::address_of(&span, &refs).unwrap()
}

/// xorshift64: the random sizes and splits below, reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn streaming_agrees_with_the_recursive_rule_over_any_split() {
    let mut rng = Rng(0x5eed_5eed_5eed_5eed);
    let mut sizes: Vec<usize> = vec![
        4096 * 128 * 2 - 1,
        4096 * 128 * 2,
        4096 * 128 * 2 + 1,
        4096 * 128 * 3 + 4096,
        4096 * 128 * 127 + 1,
    ];
    for _ in 0..40 {
        sizes.push(rng.below(3 * 1024 * 1024) as usize);
    }
    let input = content("splits", *sizes.iter().max().unwrap());
    for size in sizes {
        let data = &input[..size];
        let mut chunker = Chunker::new();
        let mut offset = 0;
        let mut sealed = 0u64;
        while offset < size {
            let piece = match rng.below(4) {
                0 => rng.below(64) as usize,
                1 => rng.below(8192) as usize,
                _ => rng.below(200_000) as usize,
            }
            .min(size - offset);
            chunker
                .write(&data[offset..offset + piece], &mut |_| sealed += 1)
                .unwrap();
            offset += piece;
        }
        assert_eq!(chunker.written(), size as u64);
        let root = chunker.finish(&mut |_| sealed += 1);
        assert_eq!(root.address(), model(data), "{size}");
    }
    // Byte by byte across a level boundary.
    let data = &input[..4096 * 128 + 4097];
    let (_, root) = stream(data, 1);
    assert_eq!(root.address(), model(data));
}

/// A minimal ustar and GNU long-link reader, with the checksum checked:
/// what a node reads from a tar.
fn read_tar(body: &[u8]) -> Vec<(String, Vec<u8>)> {
    fn octal(field: &[u8]) -> u64 {
        let text = std::str::from_utf8(field).unwrap();
        u64::from_str_radix(text.trim_end_matches(['\0', ' ']), 8).unwrap()
    }
    fn text(field: &[u8]) -> String {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        String::from_utf8(field[..end].to_vec()).unwrap()
    }
    let mut out = Vec::new();
    let mut at = 0;
    let mut long_name = None;
    loop {
        let h = &body[at..at + 512];
        if h.iter().all(|&b| b == 0) {
            assert!(body[at..].iter().all(|&b| b == 0));
            assert_eq!(body.len() - at, 1024);
            return out;
        }
        let mut sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        sum -= h[148..156].iter().map(|&b| u64::from(b)).sum::<u64>();
        sum += 8 * u64::from(b' ');
        assert_eq!(octal(&h[148..154]), sum);
        let size = octal(&h[124..135]) as usize;
        let data = body[at + 512..at + 512 + size].to_vec();
        at += 512 + size.div_ceil(512) * 512;
        match h[156] {
            b'L' => long_name = Some(text(&data)),
            b'0' => {
                let prefix = text(&h[345..500]);
                let name = text(&h[..100]);
                let path = long_name.take().unwrap_or(if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                });
                out.push((path, data));
            }
            other => panic!("type {other}"),
        }
    }
}

fn core_tar(case: &Value) -> Vec<u8> {
    let mtime = case["mtime_ms"].as_u64().unwrap() / 1000;
    let entries: Vec<(String, Vec<u8>)> = case["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["path"].as_str().unwrap().to_owned(), data(&e["data"])))
        .collect();
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, d)| (p.as_str(), d.as_slice()))
        .collect();
    let whole = tar::write(&refs, mtime).unwrap();
    // The streaming writer, its data passed in odd pieces, writes the same.
    let mut writer = TarWriter::new(mtime).unwrap();
    let mut streamed = Vec::new();
    for (path, d) in &entries {
        streamed.extend_from_slice(&writer.begin(path, d.len() as u64).unwrap());
        for piece in d.chunks(333) {
            writer.data(piece.len()).unwrap();
            streamed.extend_from_slice(piece);
        }
        streamed.extend_from_slice(writer.end().unwrap());
    }
    streamed.extend_from_slice(writer.finish().unwrap());
    assert_eq!(streamed, whole);
    let read: Vec<(String, Vec<u8>)> = read_tar(&whole);
    assert_eq!(read, entries, "{}", case["id"]);
    whole
}

#[test]
fn tar_bodies() {
    let all = answers();
    let list = cases(&all, "bodies", "tar");
    assert!(list.len() >= 14);
    let mut deviations = 0;
    for case in list {
        let id = case["id"].as_str().unwrap();
        let ours = core_tar(case);
        if case.get("deviation").is_none() {
            let body = &case["body"];
            assert_eq!(ours.len() as u64, body["length"].as_u64().unwrap(), "{id}");
            assert_eq!(ours, b64(&body["base64"]), "{id}");
            continue;
        }
        // F-3 (`tar-paths`): bee-js cut the name; the core keeps it.
        assert_eq!(case["deviation"], "tar-paths");
        deviations += 1;
        let reference = b64(&case["reference"]["base64"]);
        assert_ne!(ours, reference, "{id}");
        let theirs = read_tar(&reference);
        let paths: Vec<&str> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        assert!(
            theirs
                .iter()
                .zip(&paths)
                .any(|((p, _), want)| p.as_str() != *want),
            "{id}: bee-js kept every name"
        );
    }
    assert_eq!(deviations, 2);
}

/// F-3's own case, as the design states it: a 64-character name of 124
/// bytes. bee-js wrote one header with the name cut at 100 bytes; the core
/// writes a long-link entry with the whole name, then that same header.
#[test]
fn f3_keeps_a_long_non_ascii_name() {
    let all = answers();
    let case = cases(&all, "bodies", "tar")
        .into_iter()
        .find(|c| c["id"] == "tar-f3-long-non-ascii-name")
        .unwrap();
    let path = case["entries"][0]["path"].as_str().unwrap();
    assert_eq!((path.len(), path.encode_utf16().count()), (124, 64));
    let reference = b64(&case["reference"]["base64"]);
    let ours = core_tar(case);
    let link = 512 + (path.len() + 1).div_ceil(512) * 512;
    assert_eq!(&ours[link..], &reference[..]);
    assert_eq!(&ours[..13], b"././@LongLink");
    assert_eq!(&ours[512..512 + path.len()], path.as_bytes());
    // What bee-js's header names: the first 100 bytes, its extension lost.
    assert_eq!(read_tar(&reference)[0].0.len(), 100);
}

fn key(v: &Value) -> SigningKey {
    SigningKey::from_slice(&bytes(v)).unwrap()
}

#[test]
fn soc_bodies() {
    let all = answers();
    let list = cases(&all, "bodies", "soc");
    assert!(list.len() >= 5);
    for case in list {
        let id = case["id"].as_str().unwrap();
        let payload = data(&case["data"]);
        let identifier = b32(&case["identifier"]);
        let span = case
            .get("span")
            .map(|s| s.as_str().unwrap().parse().unwrap());
        let signed = fc_swarm::sign_soc(&key(&case["key"]), &identifier, span, &payload).unwrap();
        let result = &case["result"];
        assert_eq!(
            signed.span.to_string(),
            result["span"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            hex::encode(signed.chunk_address),
            result["chunk_address"],
            "{id}"
        );
        assert_eq!(hex::encode(signed.signature), result["signature"], "{id}");
        assert_eq!(hex::encode(signed.owner), result["owner"], "{id}");
        assert_eq!(hex::encode(signed.soc_address), result["address"], "{id}");
        assert_eq!(
            hex::encode(soc::address(&identifier, &signed.owner)),
            result["address"],
            "{id}"
        );
        let body = soc::body(&identifier, &signed, &payload).unwrap();
        assert_eq!(hex::encode(&body), result["body"], "{id}");
        assert_eq!(
            soc::upload_body(&identifier, &signed, &payload).unwrap(),
            body[soc::HEADER..].to_vec()
        );
    }
}

#[test]
fn feed_topics_and_identifiers() {
    let all = answers();
    let topics = cases(&all, "feeds", "topic");
    assert!(topics.len() >= 5);
    for case in topics {
        let name = case["name"].as_str().unwrap();
        assert_eq!(
            hex::encode(feed::topic(name)),
            case["topic"],
            "{}",
            case["id"]
        );
    }
    let identifiers = cases(&all, "feeds", "identifier");
    assert!(identifiers.len() >= 14);
    for case in identifiers {
        let index: u64 = case["index"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            hex::encode(feed::identifier(&b32(&case["topic"]), index)),
            case["identifier"],
            "{}",
            case["id"]
        );
    }
}

#[test]
fn feed_updates() {
    let all = answers();
    let list = cases(&all, "feeds", "update");
    assert!(list.len() >= 9);
    let mut forms = HashMap::<&str, usize>::new();
    for case in list {
        let id = case["id"].as_str().unwrap();
        let topic = feed::topic(case["topic"].as_str().unwrap());
        let index: u64 = case["index"].as_str().unwrap().parse().unwrap();
        let identifier = feed::identifier(&topic, index);
        let update = if case["form"] == "reference" {
            *forms.entry("reference").or_default() += 1;
            let at = case["at"].as_f64().unwrap().floor() as u64;
            Update::reference(at, &b32(&case["reference"]))
        } else {
            let payload = data(&case["data"]);
            if let Some(error) = case.get("error") {
                assert!(error.as_str().unwrap().contains("payload size 0"));
                assert_eq!(
                    Update::inline(&payload),
                    Err(feed::FeedError::PayloadSize(0))
                );
                *forms.entry("refused").or_default() += 1;
                continue;
            }
            if payload.len() <= CHUNK_SIZE {
                *forms.entry("inline").or_default() += 1;
                Update::inline(&payload).unwrap()
            } else {
                // The core's own root of what it streamed to /bytes, which
                // is the reference bee-js's upload got and wrapped.
                *forms.entry("wrapped").or_default() += 1;
                let upload = &case["bytes_upload"];
                assert_eq!(upload["length"].as_u64().unwrap() as usize, payload.len());
                assert_eq!(hex::encode(Sha256::digest(&payload)), upload["sha256"]);
                let (_, root) = stream(&payload, 131_072);
                let get = format!("GET /chunks/{}", hex::encode(root.address()));
                assert!(
                    case["requests"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| *r == get[..])
                );
                Update::wrap(&root).unwrap()
            }
        };
        let prepared = update.prepare(&identifier).unwrap();
        let signing = key(&case["key"]);
        let signature = fc_evm::sign_digest(&signing, &prepared.digest()).unwrap();
        let signed = prepared.finish(signature, fc_evm::address_of(&signing));
        let want = &case["soc"];
        assert_eq!(hex::encode(signed.owner), want["owner"], "{id}");
        assert_eq!(hex::encode(identifier), want["identifier"], "{id}");
        assert_eq!(hex::encode(signed.signature), want["sig"], "{id}");
        assert_eq!(hex::encode(signed.soc_address), want["address"], "{id}");
        assert_eq!(
            hex::encode(feed::update_address(&signed.owner, &topic, index)),
            want["address"],
            "{id}"
        );
        let body = soc::upload_body(&identifier, &signed, update.payload()).unwrap();
        assert_eq!(hex::encode(body), want["body"], "{id}");
    }
    for form in ["reference", "inline", "wrapped", "refused"] {
        assert!(
            forms.get(form).is_some_and(|n| *n >= 1),
            "{form}: {forms:?}"
        );
    }
}

/// The candidate counts a split tries, `step` by `step`; returns the
/// outcome and checks that no step tried more than it was asked.
fn split_search(case: &Value, mut next: impl FnMut() -> u32) -> Step {
    let mut miner = Miner::new(
        &b32(&case["target"]),
        &b32(&case["identifier"]),
        case["proximity"].as_u64().unwrap() as u32,
    );
    loop {
        let before = miner.tried();
        let n = next();
        let step = miner.step(n);
        assert!(miner.tried() - before <= n, "{}", case["id"]);
        if step != Step::More {
            return step;
        }
        assert_eq!(miner.tried() - before, n, "{}", case["id"]);
    }
}

#[test]
fn gsoc_signers() {
    let all = answers();
    let list = cases(&all, "gsoc", "");
    assert!(list.len() >= 14);
    let mut rng = Rng(0x0b33);
    for case in list {
        let id = case["id"].as_str().unwrap();
        let target = b32(&case["target"]);
        let identifier = b32(&case["identifier"]);
        let proximity = case["proximity"].as_u64().unwrap() as u32;
        let mined = gsoc::mine(&target, &identifier, proximity);
        match case.get("result") {
            Some(want) => {
                let signer = mined.unwrap_or_else(|| panic!("{id}: none"));
                assert_eq!(
                    u64::from(signer.index()),
                    want["index"].as_u64().unwrap(),
                    "{id}"
                );
                assert_eq!(hex::encode(signer.key_bytes()), want["key"], "{id}");
                assert_eq!(hex::encode(signer.owner()), want["owner"], "{id}");
                assert_eq!(hex::encode(signer.soc_address()), want["address"], "{id}");
                assert_eq!(
                    fc_evm::address_of(&signer.signing_key().unwrap()),
                    signer.owner()
                );
                assert!(gsoc::proximity(&signer.soc_address(), &target) >= proximity);
            }
            None => {
                assert!(case["error"].as_str().unwrap().contains("Could not mine"));
                assert_eq!(mined, None, "{id}");
            }
        }
        let expected = mined.map_or(Step::Exhausted, Step::Found);
        // Any split into steps finds the same signer.
        assert_eq!(split_search(case, || 256), expected, "{id}");
        assert_eq!(split_search(case, || 255), expected, "{id}");
        assert_eq!(split_search(case, || 4_096), expected, "{id}");
        assert_eq!(
            split_search(case, || rng.below(700) as u32 + 1),
            expected,
            "{id}"
        );
        let mut first = true;
        assert_eq!(
            split_search(case, || if std::mem::take(&mut first) { 0 } else { 33 }),
            expected,
            "{id}"
        );
    }
}

/// One candidate per step across the whole search: the most steps any
/// split can take.
#[test]
fn gsoc_one_candidate_a_step() {
    let all = answers();
    let case = cases(&all, "gsoc", "")
        .into_iter()
        .find(|c| c["id"] == "gsoc-last-candidate")
        .unwrap();
    match split_search(case, || 1) {
        Step::Found(signer) => assert_eq!(signer.index(), gsoc::CANDIDATES - 1),
        other => panic!("{other:?}"),
    }
}
