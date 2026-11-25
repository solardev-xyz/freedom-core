//! fc-swarm's write side against vectors/swarm.json (design 0015, SWM-1),
//! the window.swarm vectors from the swarm reference at bee-js 13.2.0 and
//! core-sdk 0.2.2: its `trees`, `bodies`, `feeds` and `gsoc`, byte for byte,
//! as SWM-2's done-when asks. `write_side.rs` keeps SWM-2's own answers
//! (tests/data/write-side.json); the record shapes are the same.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use base64::Engine;
use fc_swarm::chunker::{Chunker, Root};
use fc_swarm::feed::{self, Update};
use fc_swarm::gsoc;
use fc_swarm::tar::{self, TarWriter};
use fc_swarm::{CHUNK_SIZE, soc};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/swarm.json");
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

/// A data spec: { utf8 }, { hex }, { base64 } or { seed, length }.
fn data(spec: &Value) -> Vec<u8> {
    if let Some(text) = spec["utf8"].as_str() {
        return text.as_bytes().to_vec();
    }
    if let Some(h) = spec["hex"].as_str() {
        return hex::decode(h).unwrap();
    }
    if let Some(b) = spec["base64"].as_str() {
        return b64(b);
    }
    content(
        spec["seed"].as_str().unwrap(),
        spec["length"].as_u64().unwrap() as usize,
    )
}

fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

fn b32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn section<'a>(all: &'a Value, name: &str, kind: &str) -> Vec<&'a Value> {
    all[name]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| kind.is_empty() || c["kind"] == kind)
        .collect()
}

struct Owned {
    address: [u8; 32],
    span: u64,
    payload: Vec<u8>,
}

fn stream(input: &[u8], piece: usize) -> (Vec<Owned>, Root) {
    let mut chunks = Vec::new();
    let mut sink = |c: fc_swarm::chunker::Sealed<'_>| {
        chunks.push(Owned {
            address: c.address,
            span: c.span,
            payload: c.payload.to_vec(),
        })
    };
    let mut chunker = Chunker::new();
    for part in input.chunks(piece.max(1)) {
        chunker.write(part, &mut sink).unwrap();
    }
    let root = chunker.finish(&mut sink);
    (chunks, root)
}

/// SHA-256 over every chunk sorted by address: address ‖ u64_le(span) ‖ payload.
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

#[test]
fn trees() {
    let all = vectors();
    let list = section(&all, "trees", "");
    let lengths: Vec<u64> = list
        .iter()
        .map(|c| c["data"]["length"].as_u64().unwrap())
        .collect();
    assert_eq!(
        lengths,
        [0, 1, 4095, 4096, 4097, 524_288, 524_289, 10 * 1024 * 1024]
    );
    for case in list {
        let id = case["id"].as_str().unwrap();
        let input = data(&case["data"]);
        let (mut chunks, root) = stream(&input, 1000);
        assert_eq!(hex::encode(root.address()), case["root"], "{id}");
        assert_eq!(root.span(), case["span"].as_u64().unwrap(), "{id}");
        assert_eq!(hex::encode(root.payload()), case["payload"], "{id}");
        chunks.push(Owned {
            address: root.address(),
            span: root.span(),
            payload: root.payload().to_vec(),
        });
        assert_eq!(
            chunks.len() as u64,
            case["chunks"]["count"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(digest(&chunks), case["chunks"]["sha256"], "{id}");
    }
}

/// A minimal ustar and GNU long-link reader, with the checksum checked.
fn read_tar(body: &[u8]) -> Vec<(String, Vec<u8>)> {
    fn octal(field: &[u8]) -> u64 {
        let text = std::str::from_utf8(field).unwrap();
        u64::from_str_radix(text.trim_end_matches(['\0', ' ']), 8).unwrap()
    }
    fn text(field: &[u8]) -> String {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        String::from_utf8_lossy(&field[..end]).into_owned()
    }
    let mut out = Vec::new();
    let mut at = 0;
    let mut long_name = None;
    loop {
        let h = &body[at..at + 512];
        if h.iter().all(|&b| b == 0) {
            assert_eq!(body.len() - at, 1024);
            return out;
        }
        let mut sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        sum -= h[148..156].iter().map(|&b| u64::from(b)).sum::<u64>();
        sum += 8 * u64::from(b' ');
        assert_eq!(octal(&h[148..154]), sum);
        let size = octal(&h[124..135]) as usize;
        let content = body[at + 512..at + 512 + size].to_vec();
        at += 512 + size.div_ceil(512) * 512;
        match h[156] {
            b'L' => long_name = Some(text(&content)),
            b'0' => {
                let prefix = text(&h[345..500]);
                let name = text(&h[..100]);
                let path = long_name.take().unwrap_or(if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                });
                out.push((path, content));
            }
            other => panic!("type {other}"),
        }
    }
}

fn core_tar(case: &Value) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
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
    // The streaming writer, as an upload builds it, writes the same.
    let mut writer = TarWriter::new(mtime).unwrap();
    let mut streamed = Vec::new();
    for (path, d) in &entries {
        streamed.extend_from_slice(&writer.begin(path, d.len() as u64).unwrap());
        for piece in d.chunks(65_536) {
            writer.data(piece.len()).unwrap();
            streamed.extend_from_slice(piece);
        }
        streamed.extend_from_slice(writer.end().unwrap());
    }
    streamed.extend_from_slice(writer.finish().unwrap());
    assert_eq!(streamed, whole);
    (whole, entries)
}

#[test]
fn tar_bodies() {
    let all = vectors();
    let list = section(&all, "bodies", "tar");
    let mut deviations = 0;
    for case in &list {
        let id = case["id"].as_str().unwrap();
        let (ours, entries) = core_tar(case);
        if case.get("deviation").is_none() {
            let body = &case["body"];
            assert_eq!(ours.len() as u64, body["length"].as_u64().unwrap(), "{id}");
            assert_eq!(sha(&ours), body["sha256"], "{id}");
            if let Some(text) = body["base64"].as_str() {
                assert_eq!(ours, b64(text), "{id}");
            }
            if entries.len() <= 10 {
                assert_eq!(read_tar(&ours), entries, "{id}");
            }
            continue;
        }
        // F-3 (`tar-paths`): bee-js cut a name; the core keeps every one.
        assert_eq!(case["deviation"], "tar-paths", "{id}");
        deviations += 1;
        let reference = b64(case["reference"]["base64"].as_str().unwrap());
        assert_ne!(ours, reference, "{id}");
        assert_eq!(read_tar(&ours), entries, "{id}");
        let theirs = read_tar(&reference);
        assert!(
            theirs
                .iter()
                .zip(&entries)
                .any(|((p, _), (want, _))| p != want),
            "{id}: bee-js kept every name"
        );
    }
    assert!(list.len() >= 12, "{}", list.len());
    assert_eq!(deviations, 2);
}

fn key(v: &Value) -> SigningKey {
    SigningKey::from_slice(&hex::decode(v.as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn soc_chunk_file_and_pss_bodies() {
    let all = vectors();
    let socs = section(&all, "bodies", "soc");
    assert!(socs.len() >= 5);
    for case in socs {
        let id = case["id"].as_str().unwrap();
        let payload = data(&case["data"]);
        let identifier = b32(&case["identifier"]);
        let span = case
            .get("span")
            .map(|s| s.as_str().unwrap().parse().unwrap());
        let signed = fc_swarm::sign_soc(&key(&case["key"]), &identifier, span, &payload).unwrap();
        let want = &case["result"];
        assert_eq!(
            signed.span.to_string(),
            want["span"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            hex::encode(signed.chunk_address),
            want["chunk_address"],
            "{id}"
        );
        assert_eq!(hex::encode(signed.signature), want["signature"], "{id}");
        assert_eq!(hex::encode(signed.owner), want["owner"], "{id}");
        assert_eq!(hex::encode(signed.soc_address), want["address"], "{id}");
        let body = soc::body(&identifier, &signed, &payload).unwrap();
        assert_eq!(hex::encode(&body), want["body"], "{id}");
    }
    // publishChunk's POST /chunks: span ‖ payload, and the address it answers.
    let chunks = section(&all, "bodies", "chunk");
    assert!(chunks.len() >= 4);
    for case in chunks {
        let id = case["id"].as_str().unwrap();
        let payload = data(&case["data"]);
        let span: u64 = case.get("span").map_or(payload.len() as u64, |s| {
            s.as_str().unwrap().parse().unwrap()
        });
        let mut body = span.to_le_bytes().to_vec();
        body.extend_from_slice(&payload);
        assert_eq!(hex::encode(&body), case["body"], "{id}");
        assert_eq!(
            hex::encode(fc_swarm::chunk_address(span, &payload).unwrap()),
            case["address"],
            "{id}"
        );
    }
    // publishData: one POST /bzz whose body is the data, its name in the
    // query. The body the core sends is held to the recorded request's own:
    // its bytes up to 8 KiB, else its length and SHA-256 (no body for none).
    let files = section(&all, "bodies", "file");
    assert!(files.len() >= 4);
    for case in files {
        let id = case["id"].as_str().unwrap();
        let body = data(&case["data"]);
        match case["request"].get("body") {
            None => assert!(body.is_empty(), "{id}: the request has no body"),
            Some(recorded) => {
                assert_eq!(recorded["bytes"], body.len() as u64, "{id}");
                match recorded.get("base64") {
                    Some(b) => assert_eq!(b64(b.as_str().unwrap()), body, "{id}"),
                    None => assert_eq!(recorded["sha256"], sha(&body), "{id}"),
                }
            }
        }
        assert_eq!(case["request"]["path"], "/bzz", "{id}");
        let name = case["name"].as_str().unwrap_or("data");
        assert_eq!(
            case["request"]["query"][0],
            serde_json::json!(["name", name]),
            "{id}"
        );
    }
    // sendPss: the topic's keccak256 and the targets in the path, the
    // compressed key as the recipient, the message as the body.
    let pss = section(&all, "bodies", "pss");
    assert!(pss.len() >= 3);
    for case in pss {
        let id = case["id"].as_str().unwrap();
        let topic = feed::topic(case["topic"].as_str().unwrap());
        assert_eq!(hex::encode(topic), case["topic_hash"], "{id}");
        let request = &case["request"];
        assert_eq!(
            request["path"].as_str().unwrap(),
            format!(
                "/pss/send/{}/{}",
                hex::encode(topic),
                case["targets"].as_str().unwrap()
            ),
            "{id}"
        );
        assert_eq!(
            request["query"][0],
            serde_json::json!(["recipient", case["recipient"]]),
            "{id}"
        );
        let message = data(&case["data"]);
        let body = request
            .get("body")
            .map_or_else(Vec::new, |b| b64(b["base64"].as_str().unwrap()));
        assert_eq!(body, message, "{id}");
    }
    // A large feed entry's /bytes path: the upload's body is the data, the
    // core's own root of it is ChunkSplitter's, and the SOC wraps that root.
    let wrapped = section(&all, "bodies", "bytes");
    assert!(wrapped.len() >= 3);
    for case in wrapped {
        let id = case["id"].as_str().unwrap();
        let input = data(&case["data"]);
        assert_eq!(sha(&input), case["bytes_upload"]["sha256"], "{id}");
        let (_, root) = stream(&input, 65_536);
        let want = &case["root"];
        assert_eq!(hex::encode(root.address()), want["address"], "{id}");
        assert_eq!(
            root.span().to_string(),
            want["span"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(hex::encode(root.payload()), want["payload"], "{id}");
        assert_eq!(
            Update::wrap(&root).unwrap().payload(),
            root.payload(),
            "{id}"
        );
        assert_eq!(hex::encode(root.wire()), case["soc_body"], "{id}");
    }
}

#[test]
fn feed_topics_identifiers_and_updates() {
    let all = vectors();
    for case in section(&all, "feeds", "topic") {
        assert_eq!(
            hex::encode(feed::topic(case["name"].as_str().unwrap())),
            case["topic"],
            "{}",
            case["id"]
        );
    }
    let identifiers = section(&all, "feeds", "identifier");
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
    let mut forms = std::collections::HashMap::<&str, usize>::new();
    for case in section(&all, "feeds", "update") {
        let id = case["id"].as_str().unwrap();
        let topic = feed::topic(case["topic"].as_str().unwrap());
        let update = if case["form"] == "reference" {
            *forms.entry("reference").or_default() += 1;
            Update::reference(case["at"].as_u64().unwrap(), &b32(&case["reference"]))
        } else {
            let payload = data(&case["data"]);
            if case.get("error").is_some() {
                // feed-service.js refuses an empty payload before anything is signed.
                assert_eq!(case["signed"], false, "{id}");
                assert_eq!(case["reason"], "payload_too_large", "{id}");
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
                // The core's own root of what it streams to /bytes: the
                // reference bee-js's upload answered and the SOC wrapped.
                *forms.entry("wrapped").or_default() += 1;
                assert_eq!(case["bytes_upload"]["sha256"], sha(&payload), "{id}");
                let (_, root) = stream(&payload, 131_072);
                let get = format!("GET /chunks/{}", hex::encode(root.address()));
                assert!(
                    case["requests"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| *r == get[..]),
                    "{id}"
                );
                Update::wrap(&root).unwrap()
            }
        };
        let index: u64 = case["index"].as_str().unwrap().parse().unwrap();
        let identifier = feed::identifier(&topic, index);
        let prepared = update.prepare(&identifier).unwrap();
        let signing = key(&case["key"]);
        let signature = fc_evm::sign_digest(&signing, &prepared.digest()).unwrap();
        let signed = prepared.finish(signature, fc_evm::address_of(&signing));
        let want = &case["soc"];
        assert_eq!(hex::encode(signed.owner), want["owner"], "{id}");
        assert_eq!(hex::encode(identifier), want["identifier"], "{id}");
        assert_eq!(hex::encode(signed.signature), want["sig"], "{id}");
        assert_eq!(hex::encode(signed.soc_address), want["address"], "{id}");
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

#[test]
fn gsoc_signers() {
    let all = vectors();
    let list = section(&all, "gsoc", "");
    assert!(list.len() >= 12);
    let mut capped = 0;
    for case in list {
        let id = case["id"].as_str().unwrap();
        let target = b32(&case["target"]);
        let mined = gsoc::mine(
            &target,
            &b32(&case["identifier"]),
            case["proximity"].as_u64().unwrap() as u32,
        );
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
                if signer.index() == gsoc::CANDIDATES - 1 {
                    capped += 1;
                }
            }
            None => {
                assert!(
                    case["error"].as_str().unwrap().contains("Could not mine"),
                    "{id}"
                );
                assert_eq!(mined, None, "{id}");
                capped += 1;
            }
        }
    }
    // The cap and the failure are both covered.
    assert_eq!(capped, 2);
}
