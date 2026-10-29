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

/// Intermediate chunks, read as Ant's joiner reads them: the level, the
/// parity count from the chunk's own span, the data references after the
/// padding, and each child's length from the parent's geometry.
#[test]
fn intermediates() {
    let all = cases();
    let list = all["swarm"]["intermediates"].as_array().unwrap();
    assert!(list.len() >= 25);
    for case in list {
        let id = &case["id"];
        let address = hex32(&case["address"]);
        let wire = bytes(&case["wire"]);
        let chunk = check_chunk(&address, &wire).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let len = case["logical_length"].as_u64().unwrap();
        assert!(!fc_swarm::tree::is_leaf(len), "{id}");
        let got = fc_swarm::tree::intermediate(&chunk, len);
        match (&case["expect"]["ok"], case["expect"]["fail"].as_str()) {
            (ok, None) if ok.is_object() => {
                let node = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
                assert_eq!(u64::from(node.level), ok["level"].as_u64().unwrap(), "{id}");
                assert_eq!(
                    node.parities as u64,
                    ok["parities"].as_u64().unwrap(),
                    "{id}"
                );
                assert_eq!(
                    node.len() as u64,
                    ok["data_references"].as_u64().unwrap(),
                    "{id}"
                );
                let children: Vec<Value> = (0..node.len())
                    .map(|i| {
                        let (a, l) = node.child(i).unwrap();
                        serde_json::json!({ "address": hex::encode(a), "length": l })
                    })
                    .collect();
                assert_eq!(Value::Array(children), ok["children"], "{id}");
                assert_eq!(node.child(node.len()), None, "{id}");
            }
            (_, Some(fail)) => assert_eq!(got.map(|_| ()).map_err(code), Err(fail), "{id}"),
            _ => panic!("{id}: no expect"),
        }
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
