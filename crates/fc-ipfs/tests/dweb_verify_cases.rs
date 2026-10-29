//! fc-ipfs against vectors/dweb-verify-cases.json's IPFS piece checks
//! (design 0009), and against every CAR Kubo answered in
//! vectors/dweb-verify.json, rebuilt from the vectors alone.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::PathBuf;

use base64::Engine;
use fc_ipfs::{Refusal, block, car, cid, dagpb, hamt, unixfs};
use serde_json::Value;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    if let Some(b) = v["base64"].as_str() {
        return B64.decode(b).unwrap();
    }
    let mut out = Vec::new();
    for part in v["parts"].as_array().unwrap() {
        if let Some(b) = part["base64"].as_str() {
            out.extend(B64.decode(b).unwrap());
        } else if let Some(n) = part["zeros"].as_u64() {
            out.resize(out.len() + n as usize, 0);
        } else {
            let unit = B64
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

/// A CID's bytes from its text: base32 for v1, base58btc for v0.
fn cid_bytes(text: &str) -> Vec<u8> {
    if let Some(b) = cid::from_base32(text) {
        return b;
    }
    const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = Vec::new();
    for c in text.bytes() {
        let mut carry = A.iter().position(|&x| x == c).unwrap() as u32;
        for b in out.iter_mut().rev() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = text.bytes().take_while(|&c| c == b'1').count();
    let mut v = vec![0; zeros];
    v.extend(out);
    v
}

fn code(r: Refusal) -> &'static str {
    match r {
        Refusal::VerificationFailed => "verification_failed",
        Refusal::Unverifiable => "unverifiable",
        Refusal::Malformed => "malformed",
    }
}

fn expect_fail(expect: &Value) -> Option<&str> {
    expect["fail"].as_str()
}

#[test]
fn blocks() {
    let cases = load("dweb-verify-cases.json");
    for c in cases["ipfs"]["blocks"].as_array().unwrap() {
        let id = &c["id"];
        let cb = cid_bytes(c["cid"].as_str().unwrap());
        let cid = cid::parse(&cb).unwrap();
        assert_eq!(cid::to_text(&cid), c["cid"], "{id}");
        let got = block::check(&cid, &bytes(&c["block"])).map_err(code);
        // freedom-ipfs's verify_block, recorded beside the case, reads the
        // hash and size only; the codec is the walk's to refuse.
        let codec_refusal = cid.codec != cid::DAG_PB && cid.codec != cid::RAW;
        let native_ok = c["native"]["verify_block"] == "ok";
        assert_eq!(
            native_ok,
            got.is_ok() || codec_refusal,
            "{id}: freedom-ipfs says {}",
            c["native"]
        );
        match expect_fail(&c["expect"]) {
            Some(f) => assert_eq!(got, Err(f), "{id}"),
            None => assert_eq!(got, Ok(()), "{id}"),
        }
    }
}

#[test]
fn dag_pb() {
    let cases = load("dweb-verify-cases.json");
    for c in cases["ipfs"]["dag_pb"].as_array().unwrap() {
        let id = &c["id"];
        let block = bytes(&c["block"]);
        let got = dagpb::decode(&block);
        let Some(ok) = c["expect"].get("ok") else {
            assert_eq!(
                got.map(|_| ()).map_err(code),
                Err(expect_fail(&c["expect"]).unwrap()),
                "{id}"
            );
            continue;
        };
        let node = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(
            node.link_count as u64,
            ok["link_count"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(
            node.data.map(|d| B64.encode(d)),
            ok["data"].as_str().map(str::to_owned),
            "{id}"
        );
        if let Some(links) = ok["links"].as_array() {
            let got: Vec<Value> = node
                .links()
                .map(|l| serde_json::json!({ "hash": cid::to_text(&l.cid), "name": l.name, "tsize": l.tsize }))
                .collect();
            assert_eq!(&got, links, "{id}");
        }
    }
}

#[test]
fn unixfs() {
    let cases = load("dweb-verify-cases.json");
    for c in cases["ipfs"]["unixfs"].as_array().unwrap() {
        let id = &c["id"];
        let block = bytes(&c["block"]);
        let node = dagpb::decode(&block).unwrap();
        let got = unixfs::decode(&node);
        let Some(ok) = c["expect"].get("ok") else {
            assert_eq!(
                got.map(|_| ()).map_err(code),
                Err(expect_fail(&c["expect"]).unwrap()),
                "{id}"
            );
            continue;
        };
        let d = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let kind = match d.kind {
            unixfs::Kind::Raw => "raw",
            unixfs::Kind::Directory => "directory",
            unixfs::Kind::File => "file",
            unixfs::Kind::Metadata => "metadata",
            unixfs::Kind::Symlink => "symlink",
            unixfs::Kind::HamtShard => "hamt_shard",
        };
        assert_eq!(kind, ok["type"], "{id}");
        assert_eq!(d.filesize, ok["filesize"].as_u64(), "{id}");
        let sizes: Vec<u64> = d.blocksizes().collect();
        let want: Vec<u64> = ok["blocksizes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(sizes, want, "{id}");
        assert_eq!(
            d.data.map_or(0, <[u8]>::len) as u64,
            ok["data_length"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(
            node.link_count as u64,
            ok["links"].as_u64().unwrap(),
            "{id}"
        );
    }
}

#[test]
fn hamt_lookups_follow_the_hash() {
    let cases = load("dweb-verify-cases.json");
    let doc = load("dweb-verify.json");
    let blocks = &doc["ipfs"]["blocks"];
    let mut n = 0;
    for c in cases["ipfs"]["hamt"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        assert_eq!(hex::encode(hamt::hash_bits(name)), c["hash_bits"], "{name}");
        let mut shard = c["root"].as_str().unwrap().to_owned();
        let mut found = None;
        for (level, expect) in c["levels"].as_array().unwrap().iter().enumerate() {
            let block = B64
                .decode(blocks[shard.as_str()].as_str().unwrap())
                .unwrap();
            let node = dagpb::decode(&block).unwrap();
            let data = unixfs::decode(&node).unwrap();
            assert_eq!(data.kind, unixfs::Kind::HamtShard);
            match hamt::step(&node, data.data.unwrap_or(&[]), name, level) {
                hamt::Step::Shard(l) => {
                    assert_eq!(l.name.unwrap(), expect["link"], "{name} at {level}");
                    shard = cid::to_text(&l.cid);
                }
                hamt::Step::Entry(l) => {
                    assert_eq!(l.name.unwrap(), expect["link"], "{name} at {level}");
                    found = Some(cid::to_text(&l.cid));
                }
                hamt::Step::Absent => {
                    assert!(expect["link"].is_null() || found.is_none(), "{name}")
                }
            }
        }
        assert_eq!(
            found.as_deref(),
            c["expect"]["ok"]["cid"].as_str(),
            "{name}"
        );
        n += 1;
    }
    assert!(n >= 60);
}

/// Reads a CAR, checking each section's block against its CID: the
/// outcome as dweb-verify-cases.json writes it.
fn read_car(body: &[u8], step: usize) -> Value {
    let mut r = car::Reader::new();
    let mut sections = Vec::new();
    for chunk in body.chunks(step) {
        let pushed = r.push(chunk);
        for s in pushed.sections {
            let c = cid::parse(s.cid()).unwrap();
            if let Err(e) = block::check(&c, s.block()) {
                return serde_json::json!({ "fail": code(e), "after": sections.len() });
            }
            sections.push(Value::String(cid::to_text(&c)));
        }
        if let Some(e) = pushed.error {
            return serde_json::json!({ "fail": code(e), "after": sections.len() });
        }
    }
    match r.finish() {
        Ok(car::End::Complete) => serde_json::json!({ "ok": { "sections": sections } }),
        Ok(car::End::Early) => serde_json::json!({ "ended": { "after": sections.len() } }),
        Err(e) => serde_json::json!({ "fail": code(e), "after": sections.len() }),
    }
}

#[test]
fn car_framing() {
    let cases = load("dweb-verify-cases.json");
    for c in cases["ipfs"]["car"].as_array().unwrap() {
        let body = bytes(&c["car"]);
        // Whole, and a byte at a time: the reader's answer doesn't depend
        // on how the bytes arrive.
        assert_eq!(
            read_car(&body, body.len().max(1)),
            c["expect"],
            "{}",
            c["id"]
        );
        assert_eq!(read_car(&body, 1), c["expect"], "{} byte by byte", c["id"]);
    }
}

/// The blocks dweb-verify.json describes: ipfs.blocks, and every leaf
/// rebuilt from its content.
fn all_blocks(ipfs: &Value) -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    for (k, v) in ipfs["blocks"].as_object().unwrap() {
        out.insert(k.clone(), B64.decode(v.as_str().unwrap()).unwrap());
    }
    let mut files: Vec<&Value> = ipfs["files"].as_array().unwrap().iter().collect();
    for d in ipfs["directories"].as_array().unwrap() {
        files.extend(d["entries"].as_array().unwrap());
    }
    for f in files {
        let data = if let Some(t) = f["text"].as_str() {
            t.as_bytes().to_vec()
        } else if f["content"].is_object() {
            let c = &f["content"];
            let unit = content(
                c["seed"].as_str().unwrap(),
                c["unit"].as_u64().unwrap() as usize,
            );
            unit.repeat(c["count"].as_u64().unwrap() as usize)
        } else {
            content(
                f["seed"].as_str().unwrap(),
                f["size"].as_u64().unwrap() as usize,
            )
        };
        for l in f["leaves"].as_array().unwrap() {
            let from = l["from"].as_u64().unwrap() as usize;
            let len = l["length"].as_u64().unwrap() as usize;
            let mut b = l["prefix"]
                .as_str()
                .map(|p| B64.decode(p).unwrap())
                .unwrap_or_default();
            b.extend_from_slice(&data[from..from + len]);
            if let Some(s) = l["suffix"].as_str() {
                b.extend(B64.decode(s).unwrap());
            }
            out.insert(l["cid"].as_str().unwrap().to_owned(), b);
        }
    }
    out
}

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

/// Every CAR Kubo answered, rebuilt from the vectors and read in uneven
/// pieces: every block passes its CID, and each ends as Kubo ended it.
#[test]
fn kubo_cars() {
    let doc = load("dweb-verify.json");
    let ipfs = &doc["ipfs"];
    let store = all_blocks(ipfs);
    let mut n = 0;
    for e in ipfs["kubo"].as_array().unwrap() {
        let body = &e["response"]["body"];
        let Some(c) = body.get("car").filter(|c| c.is_object()) else {
            continue;
        };
        let mut wire = B64.decode(c["header"].as_str().unwrap()).unwrap();
        let mut want = Vec::new();
        for cid_text in c["blocks"].as_array().unwrap() {
            let t = cid_text.as_str().unwrap();
            let cb = cid_bytes(t);
            let block = &store[t];
            let mut len = cb.len() + block.len();
            while len >= 0x80 {
                wire.push((len as u8) | 0x80);
                len >>= 7;
            }
            wire.push(len as u8);
            wire.extend_from_slice(&cb);
            wire.extend_from_slice(block);
            want.push(Value::String(t.to_owned()));
        }
        wire.extend(B64.decode(c["trailing"].as_str().unwrap()).unwrap());
        assert_eq!(
            wire.len() as u64,
            body["length"].as_u64().unwrap(),
            "{}",
            e["id"]
        );
        let got = read_car(&wire, 7919);
        let expect = if c["complete"] == true {
            serde_json::json!({ "ok": { "sections": want } })
        } else {
            serde_json::json!({ "ended": { "after": want.len() } })
        };
        assert_eq!(got, expect, "{}", e["id"]);
        n += 1;
    }
    assert!(n > 200, "{n}");
}
