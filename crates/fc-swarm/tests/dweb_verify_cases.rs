//! fc_swarm::verify against vectors/dweb-verify-cases.json's Swarm piece
//! checks (design 0009): every case's expect, and, beside it, Ant's own
//! cac_valid and soc_valid on the same bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use base64::Engine;
use fc_swarm::verify::{
    self, FeedUpdate, Refusal, check_chunk, check_feed_update, check_leaf_chunk, leaf_matches,
};
use serde_json::Value;

fn cases() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/dweb-verify-cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD;
    if let Some(b) = v["base64"].as_str() {
        return b64.decode(b).unwrap();
    }
    let mut out = Vec::new();
    for part in v["parts"].as_array().unwrap() {
        if let Some(b) = part["base64"].as_str() {
            out.extend(b64.decode(b).unwrap());
        } else if let Some(n) = part["zeros"].as_u64() {
            out.resize(out.len() + n as usize, 0);
        } else {
            let unit = b64
                .decode(part["repeat"]["base64"].as_str().unwrap())
                .unwrap();
            for _ in 0..part["repeat"]["count"].as_u64().unwrap() {
                out.extend_from_slice(&unit);
            }
        }
    }
    assert_eq!(out.len() as u64, v["length"].as_u64().unwrap());
    out
}

fn hex32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn code(r: Refusal) -> &'static str {
    match r {
        Refusal::VerificationFailed => "verification_failed",
        Refusal::Unverifiable => "unverifiable",
    }
}

#[test]
fn chunks() {
    let all = cases();
    let list = all["swarm"]["chunks"].as_array().unwrap();
    assert!(list.len() >= 15);
    for case in list {
        let id = &case["id"];
        let address = hex32(&case["address"]);
        let wire = bytes(&case["wire"]);
        let got = check_chunk(&address, &wire);
        match (&case["expect"]["ok"], case["expect"]["fail"].as_str()) {
            (ok, None) if ok.is_object() => {
                let chunk = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
                assert_eq!(hex::encode(chunk.span), ok["span_hex"], "{id}");
                assert_eq!(
                    chunk.payload.len() as u64,
                    ok["payload_length"].as_u64().unwrap(),
                    "{id}"
                );
            }
            (_, Some(fail)) => assert_eq!(got.map(|_| ()).map_err(code), Err(fail), "{id}"),
            _ => panic!("{id}: no expect"),
        }
        // Ant's two checks, on the same bytes.
        assert_eq!(
            verify::content_addressed(&address, &wire).is_some(),
            case["ant"]["cac_valid"] == true,
            "{id}"
        );
        assert_eq!(
            verify::single_owner(&address, &wire).is_some(),
            case["ant"]["soc_valid"] == true,
            "{id}"
        );
    }
}

#[test]
fn feed_updates() {
    let all = cases();
    let list = all["swarm"]["feed_updates"].as_array().unwrap();
    assert!(list.len() >= 15);
    for case in list {
        let id = &case["id"];
        let owner: [u8; 20] = hex::decode(case["owner"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let topic = hex32(&case["topic"]);
        let index = case["index"].as_u64().unwrap();
        let wire = bytes(&case["wire"]);
        assert_eq!(
            hex::encode(verify::feed_update_address(&owner, &topic, index)),
            case["address"],
            "{id}"
        );
        let got = check_feed_update(&owner, &topic, index, &wire);
        let ok = &case["expect"]["ok"];
        if ok.is_object() {
            match got.unwrap_or_else(|e| panic!("{id}: {e:?}")) {
                FeedUpdate::V1 {
                    timestamp,
                    reference,
                } => {
                    assert_eq!(ok["version"], "v1", "{id}");
                    assert_eq!(timestamp, ok["timestamp"].as_u64().unwrap(), "{id}");
                    assert_eq!(hex::encode(reference), ok["reference"], "{id}");
                }
                FeedUpdate::V2 {
                    root,
                    span,
                    payload_len,
                } => {
                    assert_eq!(ok["version"], "v2", "{id}");
                    assert_eq!(hex::encode(root), ok["root"], "{id}");
                    assert_eq!(hex::encode(span), ok["span_hex"], "{id}");
                    assert_eq!(
                        payload_len as u64,
                        ok["payload_length"].as_u64().unwrap(),
                        "{id}"
                    );
                }
            }
        } else {
            assert_eq!(
                got.map(|_| ()).map_err(code),
                Err(case["expect"]["fail"].as_str().unwrap()),
                "{id}"
            );
        }
        let address = verify::feed_update_address(&owner, &topic, index);
        assert_eq!(
            verify::single_owner(&address, &wire).is_some(),
            case["ant"]["soc_valid"] == true,
            "{id}"
        );
    }
}

#[test]
fn leaves() {
    let all = cases();
    let list = all["swarm"]["leaves"].as_array().unwrap();
    assert!(list.len() >= 8);
    for case in list {
        let id = &case["id"];
        let address = hex32(&case["address"]);
        let len = case["logical_length"].as_u64().unwrap() as usize;
        let streamed = bytes(&case["streamed"]);
        let matched = leaf_matches(&address, len, &streamed);
        let expect = &case["expect"];
        let fallback = expect["fallback"]
            .as_bool()
            .or(expect["ok"]["fallback"].as_bool())
            .unwrap();
        assert_eq!(matched, !fallback, "{id}");
        if matched {
            assert!(expect["ok"].is_object(), "{id}");
            continue;
        }
        let wire = bytes(&case["chunk"]);
        let got = check_leaf_chunk(&address, len, &streamed, &wire).map_err(code);
        match expect["fail"].as_str() {
            Some(fail) => assert_eq!(got, Err(fail), "{id}"),
            None => assert_eq!(got, Ok(()), "{id}"),
        }
    }
}

/// Every data tree in dweb-verify.json, walked with fc_swarm::tree from its
/// root: the intermediate chunks read are the ones Ant's joiner read, and
/// each leaf's logical length and address are its content's, except
/// Ant's one-reference wrappers (freedom-hq/ant#234), which pass as leaves
/// through the /chunks fallback.
#[test]
fn trees() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/dweb-verify.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut walked = 0;
    for f in doc["swarm"]["files"].as_array().unwrap() {
        let size = f["size"].as_u64().unwrap();
        if size <= 4096 {
            continue;
        }
        let mut walk = Walk {
            id: f["id"].as_str().unwrap().to_owned(),
            chunks: &doc["swarm"]["chunks"],
            content: content(f["seed"].as_str().unwrap(), size as usize),
            wrappers: f["lone_leaf_wrappers"]
                .as_array()
                .map(|a| a.iter().map(|w| w.as_str().unwrap().to_owned()).collect())
                .unwrap_or_default(),
            read: BTreeSet::new(),
            offset: 0,
            leaves: 0,
        };
        let root = hex32(&f["root"]);
        let root_chunk = walk.wire(&hex::encode(root));
        let span: [u8; 8] = root_chunk[..8].try_into().unwrap();
        assert_eq!(fc_swarm::tree::decode_span(&span).1, size, "{}", walk.id);
        walk.node(root, size);
        assert_eq!(walk.offset, size, "{}", walk.id);
        assert_eq!(
            walk.leaves,
            f["data_leaves"].as_u64().unwrap(),
            "{}",
            walk.id
        );
        let tree: BTreeSet<String> = f["tree"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(walk.read, tree, "{}: the chunks read", walk.id);
        walked += 1;
    }
    assert!(walked >= 20, "{walked}");
}

struct Walk<'a> {
    id: String,
    chunks: &'a Value,
    content: Vec<u8>,
    wrappers: BTreeSet<String>,
    read: BTreeSet<String>,
    offset: u64,
    leaves: u64,
}

impl Walk<'_> {
    fn wire(&self, hex: &str) -> Vec<u8> {
        let b = self.chunks[hex]
            .as_str()
            .unwrap_or_else(|| panic!("{}: chunk {hex}", self.id));
        base64::engine::general_purpose::STANDARD.decode(b).unwrap()
    }

    fn node(&mut self, address: [u8; 32], len: u64) {
        let hex = hex::encode(address);
        if fc_swarm::tree::is_leaf(len) {
            let l = len as usize;
            if self.wrappers.contains(&hex) {
                // Ant streams the wrapper's first payload bytes, which its
                // chunk authenticates.
                self.read.insert(hex.clone());
                let w = self.wire(&hex);
                let served = w[8..8 + l].to_vec();
                assert!(!verify::leaf_matches(&address, l, &served), "{}", self.id);
                assert_eq!(
                    verify::check_leaf_chunk(&address, l, &served, &w),
                    Ok(()),
                    "{}",
                    self.id
                );
            } else {
                let from = self.offset as usize;
                assert!(
                    verify::leaf_matches(&address, l, &self.content[from..from + l]),
                    "{}: the leaf at {from}",
                    self.id
                );
            }
            self.offset += len;
            self.leaves += 1;
            return;
        }
        self.read.insert(hex.clone());
        let w = self.wire(&hex);
        let chunk = check_chunk(&address, &w).unwrap_or_else(|e| panic!("{}: {e:?}", self.id));
        let node = fc_swarm::tree::intermediate(&chunk, len)
            .unwrap_or_else(|e| panic!("{}: {e:?}", self.id));
        let children: Vec<([u8; 32], u64)> =
            (0..node.len()).map(|i| node.child(i).unwrap()).collect();
        for (child, child_len) in children {
            self.node(child, child_len);
        }
    }
}

/// content(seed, n): SHA-256(seed ‖ u64_be(i)), concatenated.
fn content(seed: &str, n: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
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

/// Every manifest lookup in dweb-verify.json (ant-retrieval's lookup_path
/// answers), replayed with fc_swarm::manifest: the nodes come from the
/// recorded chunks, joined with fc_swarm::tree.
#[test]
fn manifest_lookups() {
    use fc_swarm::manifest::{self, Lookup, Outcome, Step};
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/dweb-verify.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let chunks = &doc["swarm"]["chunks"];
    let mut checked = 0;
    for m in doc["swarm"]["manifests"].as_array().unwrap() {
        let id = m["id"].as_str().unwrap();
        let root = join_node(chunks, &hex32(&m["root"]));
        for l in m["lookups"].as_array().unwrap() {
            let p = l["path"].as_str().unwrap();
            let (mut lookup, mut step) = Lookup::new(manifest::parse_node(&root).unwrap(), p);
            let outcome = loop {
                match step {
                    Step::Done(o) => break Some(o),
                    Step::Failed(e) => panic!("{id} {p:?}: {e:?}"),
                    Step::Need(r) if r.len() == 64 => break None,
                    Step::Need(r) => {
                        let bytes = join_node(chunks, &r.try_into().unwrap());
                        step = lookup.node(&bytes);
                    }
                }
            };
            let Some(outcome) = outcome else {
                // An encrypted node below a plain root: the walk refuses it
                // (encrypted-in-walk); Ant decrypts and finds the entry.
                assert_eq!(
                    l["data_ref"].as_str().map(str::len),
                    Some(128),
                    "{id} {p:?}"
                );
                continue;
            };
            match (outcome, l["error"].as_str()) {
                (Outcome::Found { data_ref, metadata }, None) => {
                    assert_eq!(hex::encode(&data_ref), l["data_ref"], "{id} {p:?}");
                    assert_eq!(
                        metadata.get(manifest::CONTENT_TYPE),
                        l["content_type"].as_str(),
                        "{id} {p:?}"
                    );
                    for key in [manifest::CONTENT_TYPE, manifest::FILENAME] {
                        assert_eq!(
                            metadata.get(key),
                            l["metadata"][key].as_str(),
                            "{id} {p:?} {key}"
                        );
                    }
                }
                (Outcome::NotFound { root }, Some(e)) => {
                    let shown = if root {
                        "(root)".to_owned()
                    } else {
                        p.trim_start_matches('/').to_owned()
                    };
                    assert_eq!(e, format!("path '{shown}' not found"), "{id} {p:?}");
                }
                (Outcome::Directory, Some(e)) => {
                    assert_eq!(
                        e,
                        format!(
                            "path '{}' is a directory (redirect to trailing slash)",
                            p.trim_start_matches('/')
                        ),
                        "{id} {p:?}"
                    );
                }
                (o, e) => panic!("{id} {p:?}: {o:?} where Ant says {e:?}"),
            }
            checked += 1;
        }
    }
    assert!(checked >= 100, "{checked}");
}

/// A manifest node's bytes: its chunk tree, joined.
fn join_node(chunks: &Value, address: &[u8; 32]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let wire = b64
        .decode(chunks[hex::encode(address)].as_str().unwrap())
        .unwrap();
    let chunk = check_chunk(address, &wire).unwrap();
    let (_, len) = fc_swarm::tree::decode_span(&chunk.span);
    if fc_swarm::tree::is_leaf(len) {
        return chunk.payload[..len as usize].to_vec();
    }
    let node = fc_swarm::tree::intermediate(&chunk, len).unwrap();
    let mut out = Vec::new();
    for i in 0..node.len() {
        let (child, child_len) = node.child(i).unwrap();
        let w = b64
            .decode(chunks[hex::encode(child)].as_str().unwrap())
            .unwrap();
        let c = check_chunk(&child, &w).unwrap();
        assert!(fc_swarm::tree::is_leaf(child_len));
        out.extend_from_slice(&c.payload[..child_len as usize]);
    }
    out
}
