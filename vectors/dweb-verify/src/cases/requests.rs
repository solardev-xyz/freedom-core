//! Whole requests through the verifier (0009, Tests first: the adversarial
//! vectors): a plan, a world (the honest node of dweb-verify.json with one
//! thing changed), and what the page gets: the head and the body, the
//! error before the head, or the head and the prefix released before the
//! body is cut.
//!
//! Heads and bodies the verifier must reproduce are copied from the
//! bundled node's recorded answers (Ant's exchanges, GatewayCore's native
//! ones), less the headers that describe the node; every failure is the
//! design's, written out here.

use super::swarm::{Addr, cac, owner, secret, soc, soc_address, span};
use super::{Err, bytes};
use crate::content;
use crate::mantaray::{self, Fork, Node};
use base64::Engine;
use serde_json::{Value, json};

const SWARM_FAILED: &str = "Swarm content verification failed";
const SWARM_UNVERIFIABLE: &str = "This content can't be verified with the external Swarm node";
const SWARM_404: &str = "Not found on the external Swarm node";
const SWARM_STOPPED: &str = "The external Swarm node stopped sending";
const IPFS_FAILED: &str = "IPFS content verification failed";
const IPFS_UNVERIFIABLE: &str = "This content can't be verified with the external IPFS gateway";
const IPFS_404: &str = "Not found on the external IPFS gateway";
const IPFS_STOPPED: &str = "The external IPFS gateway stopped sending";
const IPFS_MALFORMED: &str = "This IPFS content is malformed";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

struct Doc(Value);

impl Doc {
    fn exchange(&self, id: &str) -> Result<&Value, Err> {
        for section in [&self.0["swarm"]["exchanges"], &self.0["ipfs"]["native"]] {
            if let Some(e) = section
                .as_array()
                .and_then(|a| a.iter().find(|e| e["id"] == id))
            {
                return Ok(e);
            }
        }
        Err(format!("exchange {id} isn't in dweb-verify.json").into())
    }

    /// The head the verifier must write: the bundled node's, less the
    /// headers that describe the node (meta.ant.node_headers).
    fn head(&self, id: &str, content: &str) -> Result<Value, Err> {
        let r = &self.exchange(id)?["response"];
        let node: Vec<&str> = self.0["meta"]["ant"]["node_headers"]["names"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let headers: Vec<Value> = r["headers"]
            .as_array()
            .ok_or("headers")?
            .iter()
            .filter(|kv| !node.contains(&kv[0].as_str().unwrap_or_default()))
            .cloned()
            .collect();
        Ok(json!({
            "status": r["status"],
            "headers": headers,
            "trust": { "name": null, "content": content },
            "from": id,
        }))
    }

    fn body(&self, id: &str) -> Result<Value, Err> {
        Ok(self.exchange(id)?["response"]["body"].clone())
    }

    fn chunk(&self, addr: &str) -> Result<Vec<u8>, Err> {
        let b = self.0["swarm"]["chunks"][addr]
            .as_str()
            .ok_or_else(|| format!("chunk {addr}"))?;
        Ok(B64.decode(b)?)
    }
}

fn content_body(seed: &str, from: usize, length: usize) -> Value {
    if length == 0 {
        return json!({ "length": 0 });
    }
    json!({ "content": { "seed": seed, "from": from, "length": length } })
}

fn complete(head: Value, body: Value) -> Value {
    json!({ "head": head, "body": body })
}

fn error(status: u16, message: &str) -> Value {
    json!({ "error": { "status": status, "body": { "code": status, "message": message } } })
}

fn truncated(head: Value, released: Value, code: &str, message: &str) -> Value {
    json!({
        "head": head,
        "truncated": { "released": released, "abort": { "code": code, "message": message } },
    })
}

/// A plan's members the verifier reads; the rest (retry, timers, response,
/// trust) are the backend's as dweb.open writes them.
fn swarm_plan(root: &str, path: &str, headers: &[(&str, &str)]) -> Value {
    json!({
        "node": "ant",
        "root": { "swarm": root },
        "path": path,
        "query": "",
        "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
    })
}

fn ipfs_plan(root: Value, path: &str, headers: &[(&str, &str)]) -> Value {
    json!({
        "node": "ipfs",
        "root": root,
        "path": path,
        "query": "",
        "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
    })
}

struct Cases(Vec<Value>);

impl Cases {
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        id: &str,
        note: &str,
        plan: Value,
        method: &str,
        world: Value,
        expect: Value,
        deviation: Option<&str>,
    ) {
        let mut case = json!({
            "id": id,
            "note": note,
            "plan": plan,
            "method": method,
            "partition": null,
            "world": world,
            "expect": expect,
        });
        if let Some(d) = deviation {
            case["deviation"] = json!(d);
        }
        self.0.push(case);
    }
}

fn world(changes: Value) -> Value {
    json!({ "changes": changes })
}

async fn swarm(doc: &Doc, out: &mut Cases) -> Result<(), Err> {
    // site-a: style.css is 5,000 bytes, a root over two leaves.
    let site = doc.0["swarm"]["manifests"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["id"] == "site-a"))
        .ok_or("site-a")?;
    let site_root = site["root"].as_str().ok_or("root")?.to_string();
    let style = site["entries"]
        .as_array()
        .and_then(|e| e.iter().find(|e| e["path"] == "style.css"))
        .ok_or("style.css")?;
    let style_ref = style["data_ref"].as_str().ok_or("data_ref")?.to_string();
    let get_style = || swarm_plan(&site_root, "/style.css", &[]);
    let head_style = || doc.head("site-a#8", "verified");
    let style_body = content_body("site-style", 0, 5000);

    out.push(
        "swarm/honest",
        "style.css from site-a, nothing changed: the bundled Ant's answer",
        get_style(),
        "GET",
        world(json!([])),
        complete(head_style()?, style_body.clone()),
        None,
    );
    out.push("swarm/leaf-1-flipped", "the /bytes stream's byte 4106 (in the second leaf) flipped: the first leaf is released, the second fails its check, its /chunks fallback is honest", get_style(), "GET",
        world(json!([{ "piece": "bytes", "reference": style_ref, "flip": 4106 }])),
        truncated(head_style()?, content_body("site-style", 0, 4096), "verification_failed", SWARM_FAILED), None);
    out.push(
        "swarm/leaf-0-flipped",
        "the stream's byte 10 flipped: nothing is released",
        get_style(),
        "GET",
        world(json!([{ "piece": "bytes", "reference": style_ref, "flip": 10 }])),
        truncated(
            head_style()?,
            content_body("site-style", 0, 0),
            "verification_failed",
            SWARM_FAILED,
        ),
        None,
    );
    out.push("swarm/leaf-flipped-in-both", "the stream's byte 10 and the same byte of the leaf /chunks answers flipped", get_style(), "GET",
        world(json!([
            { "piece": "bytes", "reference": style_ref, "flip": 10 },
            { "piece": "chunk", "address": h(&cac(span(4096), &content::bytes("site-style", 5000)[..4096])?.0), "flip": 18 },
        ])),
        truncated(head_style()?, content_body("site-style", 0, 0), "verification_failed", SWARM_FAILED), None);
    out.push(
        "swarm/file-root-flipped",
        "the file's root chunk with a byte flipped: before the head",
        get_style(),
        "GET",
        world(json!([{ "piece": "chunk", "address": style_ref, "flip": 13 }])),
        error(502, SWARM_FAILED),
        None,
    );
    out.push(
        "swarm/manifest-flipped",
        "the manifest's root node with a byte flipped",
        get_style(),
        "GET",
        world(json!([{ "piece": "chunk", "address": site_root, "flip": 100 }])),
        error(502, SWARM_FAILED),
        None,
    );
    let mut over = doc.chunk(&style_ref)?;
    over.resize(8 + 4097, 0);
    out.push("swarm/root-over-chunk-size", "the file's root answered with its payload zero-extended to 4,097 bytes: past the chunk size", get_style(), "GET",
        world(json!([{ "piece": "chunk", "address": style_ref, "wire": bytes(&over) }])),
        error(502, SWARM_FAILED), None);
    out.push(
        "swarm/head-reads-no-leaf",
        "HEAD with a leaf flipped: a HEAD stops after the file's root, so it isn't read",
        swarm_plan(&site_root, "/style.css", &[]),
        "HEAD",
        world(json!([{ "piece": "bytes", "reference": style_ref, "flip": 10 }])),
        complete(doc.head("site-a#9", "verified")?, json!({ "length": 0 })),
        None,
    );

    // Ranges, on style.css's second leaf.
    let range = || swarm_plan(&site_root, "/style.css", &[("range", "bytes=4096-")]);
    out.push("swarm/range-200-whole", "the node ignores Range and answers 200 with the whole file: the first leaf is skipped unread, the second checked", range(), "GET",
        world(json!([{ "piece": "bytes", "reference": style_ref, "answer": "whole" }])),
        complete(doc.head("site-a#37", "verified")?, doc.body("site-a#37")?), None);
    out.push(
        "swarm/range-200-at-zero",
        "a 200 holding the range's bytes at offset 0: it ends before the needed leaf",
        range(),
        "GET",
        world(json!([{ "piece": "bytes", "reference": style_ref, "answer": "at_zero" }])),
        truncated(
            doc.head("site-a#37", "verified")?,
            content_body("site-style", 4096, 0),
            "piece_failed",
            SWARM_STOPPED,
        ),
        None,
    );
    out.push("swarm/range-200-short", "a 200 with the whole file that ends after 4,500 bytes, inside the needed leaf", range(), "GET",
        world(json!([{ "piece": "bytes", "reference": style_ref, "answer": "whole", "end_after": 4500 }])),
        truncated(doc.head("site-a#37", "verified")?, content_body("site-style", 4096, 0), "piece_failed", SWARM_STOPPED), None);
    out.push(
        "swarm/206-short",
        "an exact 206 that ends after 4,900 bytes: the first leaf is released",
        get_style(),
        "GET",
        world(json!([{ "piece": "bytes", "reference": style_ref, "end_after": 4900 }])),
        truncated(
            head_style()?,
            content_body("site-style", 0, 4096),
            "piece_failed",
            SWARM_STOPPED,
        ),
        None,
    );
    out.push("swarm/206-other-interval", "a 206 whose Content-Range names another interval: no byte of it is used", get_style(), "GET",
        world(json!([{ "piece": "bytes", "reference": style_ref, "content_range": "bytes 0-4999/5001" }])),
        truncated(head_style()?, content_body("site-style", 0, 0), "piece_failed", SWARM_STOPPED), None);

    // file-524288-rs0: a root over 128 leaves, no manifest.
    let big = "d5bc5564ebcbeee060f251c1b4befe69514a801fb2a363635657fbee6d3c610f";
    let leaf1 = || swarm_plan(big, "/", &[("range", "bytes=4096-8191")]);
    out.push("swarm/stall-after-needed", "a 200 with the whole file that stalls after 8,192 bytes, once the needed leaf has arrived: the core has already cancelled it", leaf1(), "GET",
        world(json!([{ "piece": "bytes", "reference": big, "answer": "whole", "stall_after": 8192 }])),
        complete(doc.head("file-524288-rs0#30", "verified")?, doc.body("file-524288-rs0#30")?), None);
    out.push(
        "swarm/stall-before-needed",
        "an exact 206 that stalls after 1,000 bytes: main's body idle timer ends the piece",
        leaf1(),
        "GET",
        world(json!([{ "piece": "bytes", "reference": big, "stall_after": 1000 }])),
        truncated(
            doc.head("file-524288-rs0#30", "verified")?,
            content_body("file-524288", 4096, 0),
            "piece_failed",
            SWARM_STOPPED,
        ),
        None,
    );
    out.push(
        "swarm/leaf-5-flipped",
        "a byte of the sixth leaf flipped: five leaves are released",
        swarm_plan(big, "/", &[]),
        "GET",
        world(json!([{ "piece": "bytes", "reference": big, "flip": 5 * 4096 + 7 }])),
        truncated(
            doc.head("file-524288-rs0#3", "verified")?,
            content_body("file-524288", 0, 5 * 4096),
            "verification_failed",
            SWARM_FAILED,
        ),
        None,
    );
    out.push(
        "swarm/multi-range",
        "two ranges: Ant answers multipart/byteranges, the core the whole body with 200",
        swarm_plan(big, "/", &[("range", "bytes=0-0,2-3")]),
        "GET",
        world(json!([])),
        complete(
            doc.head("file-524288-rs0#3", "verified")?,
            doc.body("file-524288-rs0#3")?,
        ),
        Some("multi-range"),
    );

    // Pieces the node fails.
    out.push("swarm/piece-404", "the file's root answered 404, with a body of the node's own, which the page never gets", get_style(), "GET",
        world(json!([{ "piece": "chunk", "address": style_ref, "status": 404, "body": bytes(b"the node's own words") }])),
        error(404, SWARM_404), None);
    out.push("swarm/piece-500", "the file's root answered 500 at every attempt", get_style(), "GET",
        world(json!([{ "piece": "chunk", "address": style_ref, "status": 500, "body": bytes(b"the node's own words") }])),
        error(500, "The external Swarm node answered 500"), None);
    out.push(
        "swarm/path-not-found",
        "a path the verified manifest doesn't hold: Ant's 404, proven",
        swarm_plan(&site_root, "/missing", &[]),
        "GET",
        world(json!([])),
        complete(doc.head("site-a#34", "verified")?, doc.body("site-a#34")?),
        None,
    );

    // A leaf shorter than its logical length, on a tree of the cases' own.
    let head4 = content::bytes("requests-short-head", 4096);
    let tail = content::bytes("requests-short-tail", 40);
    let (l0, l0w) = cac(span(4096), &head4)?;
    let (l1, l1w) = cac(span(40), &tail)?;
    let mut refs = l0.to_vec();
    refs.extend_from_slice(&l1);
    let (root, rootw) = cac(span(4096 + 60), &refs)?;
    let mut streamed = head4.clone();
    streamed.extend_from_slice(&tail);
    streamed.resize(4096 + 60, 0);
    let raw_head = |r: &Addr, len: usize| {
        json!({
            "status": 200,
            "headers": [
                ["content-type", "application/octet-stream"],
                ["content-length", len.to_string()],
                ["accept-ranges", "bytes"],
                ["cache-control", "public, max-age=31536000, immutable"],
                ["etag", format!("\"{}\"", h(r))],
            ],
            "trust": { "name": null, "content": "verified" },
            "from": "Ant's head for a reference that isn't a manifest, as file-524288-rs0#3",
        })
    };
    out.push("swarm/leaf-payload-shorter", "a root of span 4,156 over a full leaf and a 40-byte leaf: the second leaf's payload is shorter than the 60 bytes its parent gives it", swarm_plan(&h(&root), "/", &[]), "GET",
        json!({
            "chunks": { h(&root): bytes(&rootw), h(&l0): bytes(&l0w), h(&l1): bytes(&l1w) },
            "changes": [{ "piece": "bytes", "reference": h(&root), "body": bytes(&streamed) }],
        }),
        truncated(raw_head(&root, 4156), content_body("requests-short-head", 0, 4096), "unverifiable", SWARM_UNVERIFIABLE), None);

    // Single-owner chunks off the feed path.
    let s = secret("requests-soc-owner");
    let id = ant_crypto::keccak256(b"requests-soc-id");
    let soc_addr = soc_address(&id, &owner(&s)?);
    let (leaf, leaf_w) = cac(span(100), &content::bytes("requests-soc-leaf", 100))?;
    let soc_a = soc(&s, &id, &leaf_w)?;
    let (_, other_w) = cac(span(100), &content::bytes("requests-soc-other", 100))?;
    let soc_b = soc(&s, &id, &other_w)?;
    out.push("swarm/soc-as-root", "the URL's reference is a valid single-owner chunk's address", swarm_plan(&h(&soc_addr), "/", &[]), "GET",
        json!({ "chunks": { h(&soc_addr): bytes(&soc_a), h(&leaf): bytes(&leaf_w) }, "changes": [] }),
        error(502, SWARM_UNVERIFIABLE), Some("soc-references"));
    let manifest = Node {
        obfuscation_key: [0; 32],
        ref_size: 32,
        entry: vec![0; 32],
        forks: vec![Fork {
            node_type: mantaray::TYPE_VALUE | mantaray::TYPE_WITH_METADATA,
            prefix: b"file.bin".to_vec(),
            child: soc_addr.to_vec(),
            metadata: Some(mantaray::metadata(&[
                ("Content-Type", "application/octet-stream"),
                ("Filename", "file.bin"),
            ])),
        }],
    }
    .marshal();
    let (m_root, m_wire) = cac(span(manifest.len() as u64), &manifest)?;
    out.push("swarm/soc-as-manifest-child", "a manifest whose fork for file.bin names a single-owner chunk", swarm_plan(&h(&m_root), "/file.bin", &[]), "GET",
        json!({ "chunks": { h(&m_root): bytes(&m_wire), h(&soc_addr): bytes(&soc_a), h(&leaf): bytes(&leaf_w) }, "changes": [] }),
        error(502, SWARM_UNVERIFIABLE), Some("soc-references"));
    let tail_leaf = content::bytes("requests-soc-tail", 4096);
    let (tl, tlw) = cac(span(4096), &tail_leaf)?;
    let mut refs = soc_addr.to_vec();
    refs.extend_from_slice(&tl);
    let file_span = 128 * 4096 + 4096;
    let (froot, frootw) = cac(span(file_span), &refs)?;
    out.push("swarm/soc-as-intermediate", "the URL's reference is a root of span 528,384 whose first child, an intermediate chunk's place, is a single-owner chunk: telling a raw file from a manifest reads down to the first data chunk, so the refusal comes before the head", swarm_plan(&h(&froot), "/", &[]), "GET",
        json!({ "chunks": { h(&froot): bytes(&frootw), h(&soc_addr): bytes(&soc_a), h(&tl): bytes(&tlw) }, "changes": [] }),
        error(502, SWARM_UNVERIFIABLE), Some("soc-references"));
    // The same file behind a manifest entry: the entry says it is a file,
    // so the head goes out on its root chunk, and the single-owner chunk
    // is met after it.
    let value = Node {
        obfuscation_key: [0; 32],
        ref_size: 32,
        entry: froot.to_vec(),
        forks: Vec::new(),
    }
    .marshal();
    let (v_addr, v_wire) = cac(span(value.len() as u64), &value)?;
    let entry_manifest = Node {
        obfuscation_key: [0; 32],
        ref_size: 32,
        entry: vec![0; 32],
        forks: vec![Fork {
            node_type: mantaray::TYPE_VALUE | mantaray::TYPE_WITH_METADATA,
            prefix: b"file.bin".to_vec(),
            child: v_addr.to_vec(),
            metadata: Some(mantaray::metadata(&[
                ("Content-Type", "application/octet-stream"),
                ("Filename", "file.bin"),
            ])),
        }],
    }
    .marshal();
    let (e_root, e_wire) = cac(span(entry_manifest.len() as u64), &entry_manifest)?;
    let entry_head = json!({
        "status": 200,
        "headers": [
            ["content-type", "application/octet-stream"],
            ["content-length", file_span.to_string()],
            ["accept-ranges", "bytes"],
            ["content-disposition", "inline; filename=\"file.bin\""],
            ["cache-control", "public, max-age=31536000, immutable"],
            ["etag", format!("\"{}\"", h(&froot))],
        ],
        "trust": { "name": null, "content": "verified" },
        "from": "Ant's head for a manifest entry, as site-a#8",
    });
    // Hold the head to Ant's: the same manifest over an honest file of the
    // same size, through Ant's gateway, gives these headers but the ETag.
    let honest = content::bytes("requests-soc-honest", file_span as usize);
    let split = ant_retrieval::split_bytes(&honest);
    let mut net: std::collections::HashMap<Addr, Vec<u8>> = split
        .chunks
        .into_iter()
        .map(|c| (c.address, c.wire))
        .collect();
    let value = Node {
        obfuscation_key: [0; 32],
        ref_size: 32,
        entry: split.root.to_vec(),
        forks: Vec::new(),
    }
    .marshal();
    let (hv, hvw) = cac(span(value.len() as u64), &value)?;
    net.insert(hv, hvw);
    let honest_manifest = Node {
        obfuscation_key: [0; 32],
        ref_size: 32,
        entry: vec![0; 32],
        forks: vec![Fork {
            node_type: mantaray::TYPE_VALUE | mantaray::TYPE_WITH_METADATA,
            prefix: b"file.bin".to_vec(),
            child: hv.to_vec(),
            metadata: Some(mantaray::metadata(&[
                ("Content-Type", "application/octet-stream"),
                ("Filename", "file.bin"),
            ])),
        }],
    }
    .marshal();
    let (hm, hmw) = cac(span(honest_manifest.len() as u64), &honest_manifest)?;
    net.insert(hm, hmw);
    let ant = crate::gateway::Ant::new(std::sync::Arc::new(crate::store::MemFetcher::new(net)));
    let request_headers: Vec<(String, String)> = doc.0["meta"]["request_headers"]
        .as_array()
        .ok_or("request_headers")?
        .iter()
        .map(|kv| {
            (
                kv[0].as_str().unwrap_or_default().to_string(),
                kv[1].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let answer = ant
        .send(
            "GET",
            &format!("/bzz/{}/file.bin", h(&hm)),
            &request_headers,
        )
        .await
        .map_err(|e| format!("Ant's answer for the honest entry: {e}"))?;
    let theirs: Vec<Value> = answer
        .headers
        .iter()
        .filter(|(k, _)| k != "server")
        .map(|(k, v)| {
            if k == "etag" {
                json!([k, format!("\"{}\"", h(&froot))])
            } else {
                json!([k, v])
            }
        })
        .collect();
    if answer.status != 200
        || Value::Array(theirs) != entry_head["headers"]
        || answer.body != honest
    {
        return Err("the manifest entry's head isn't Ant's".into());
    }
    out.push("swarm/soc-as-intermediate-in-manifest", "the same file as the entry file.bin of a manifest: the head goes out once the file's root chunk has passed, and its first child, a single-owner chunk, is refused after it, with nothing released", swarm_plan(&h(&e_root), "/file.bin", &[]), "GET",
        json!({ "chunks": { h(&e_root): bytes(&e_wire), h(&v_addr): bytes(&v_wire), h(&froot): bytes(&frootw), h(&soc_addr): bytes(&soc_a), h(&tl): bytes(&tlw) }, "changes": [] }),
        truncated(entry_head, content_body("requests-soc-tail", 0, 0), "unverifiable", SWARM_UNVERIFIABLE), Some("soc-references"));
    out.0.push(json!({
        "id": "swarm/soc-two-payloads",
        "note": "one owner's two SOCs at one address, served one after the other in one partition: each request is unverifiable, and nothing of the first is cached for the second",
        "partition": "requests-soc",
        "deviation": "soc-references",
        "steps": [
            {
                "plan": swarm_plan(&h(&soc_addr), "/", &[]),
                "method": "GET",
                "world": { "chunks": { h(&soc_addr): bytes(&soc_a) }, "changes": [] },
                "expect": error(502, SWARM_UNVERIFIABLE),
            },
            {
                "plan": swarm_plan(&h(&soc_addr), "/", &[]),
                "method": "GET",
                "world": { "chunks": { h(&soc_addr): bytes(&soc_b) }, "changes": [] },
                "expect": error(502, SWARM_UNVERIFIABLE),
            },
        ],
    }));

    // Feeds.
    let feed = doc.0["swarm"]["feeds"]
        .as_array()
        .and_then(|f| f.iter().find(|f| f["id"] == "feed-v1"))
        .ok_or("feed-v1")?;
    let fm = feed["manifest"].as_str().ok_or("manifest")?;
    let updates = feed["updates"].as_array().ok_or("updates")?;
    let latest = updates.last().ok_or("an update")?;
    let latest_addr = latest["address"].as_str().ok_or("address")?;
    let latest_wire = doc.chunk(latest_addr)?;
    let prev_wire = doc.chunk(
        updates[updates.len() - 2]["address"]
            .as_str()
            .ok_or("address")?,
    )?;
    let get_feed = || swarm_plan(fm, "/", &[]);
    out.push(
        "swarm/feed",
        "feed-v1, nothing changed: the latest update is accepted, latest_asserted",
        get_feed(),
        "GET",
        world(json!([])),
        complete(
            doc.head("feed-v1#1", "latest_asserted")?,
            doc.body("feed-v1#1")?,
        ),
        None,
    );
    let id_l: [u8; 32] = hex::decode(latest["id"].as_str().ok_or("id")?)?
        .try_into()
        .map_err(|_| "id length")?;
    let forged = soc(&secret("requests-not-the-owner"), &id_l, &latest_wire[97..])?;
    out.push(
        "swarm/feed-other-owner",
        "the latest update re-signed by another key, served at its address",
        get_feed(),
        "GET",
        world(json!([{ "piece": "chunk", "address": latest_addr, "wire": bytes(&forged) }])),
        error(502, SWARM_FAILED),
        None,
    );
    out.push(
        "swarm/feed-other-index",
        "the previous update's chunk served at the latest update's address",
        get_feed(),
        "GET",
        world(json!([{ "piece": "chunk", "address": latest_addr, "wire": bytes(&prev_wire) }])),
        error(502, SWARM_FAILED),
        None,
    );
    out.push(
        "swarm/feed-update-flipped",
        "the latest update with a byte of its wrapped chunk flipped",
        get_feed(),
        "GET",
        world(json!([{ "piece": "chunk", "address": latest_addr, "flip": 97 + 8 + 3 }])),
        error(502, SWARM_FAILED),
        None,
    );

    // Encrypted references met in a walk.
    let enc = doc.0["swarm"]["manifests"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["id"] == "encrypted-below-plain-root"))
        .ok_or("encrypted-below-plain-root")?;
    out.push("swarm/encrypted-in-manifest", "a plain root whose node below holds 64-byte references: Ant serves the file, the walk refuses", swarm_plan(enc["root"].as_str().ok_or("root")?, "/enc/secret.bin", &[]), "GET",
        world(json!([])), error(502, SWARM_UNVERIFIABLE), Some("encrypted-in-walk"));
    let fe = doc.0["swarm"]["feeds"]
        .as_array()
        .and_then(|f| f.iter().find(|f| f["id"] == "feed-encrypted"))
        .ok_or("feed-encrypted")?;
    out.push("swarm/encrypted-feed-update", "a feed whose latest v1 update is 80 bytes: Ant answers the manifest's own node, the walk refuses", swarm_plan(fe["manifest"].as_str().ok_or("manifest")?, "/", &[]), "GET",
        world(json!([])), error(502, SWARM_UNVERIFIABLE), Some("encrypted-in-walk"));
    Ok(())
}

fn ipfs(doc: &Doc, out: &mut Cases) -> Result<(), Err> {
    let dirs = doc.0["ipfs"]["directories"]
        .as_array()
        .ok_or("directories")?;
    let site = dirs
        .iter()
        .find(|d| d["id"] == "site-v1")
        .ok_or("site-v1")?;
    let root = site["root"].as_str().ok_or("root")?.to_string();
    let entry = |p: &str| -> Result<Value, Err> {
        site["entries"]
            .as_array()
            .and_then(|e| e.iter().find(|e| e["path"] == p))
            .cloned()
            .ok_or_else(|| format!("entry {p}").into())
    };
    let photo = entry("img/photo.jpg")?;
    let photo_root = photo["cid"].as_str().ok_or("cid")?.to_string();
    let leaf0 = photo["leaves"][0]["cid"]
        .as_str()
        .ok_or("leaf")?
        .to_string();
    let leaf1 = photo["leaves"][1]["cid"]
        .as_str()
        .ok_or("leaf")?
        .to_string();
    let plan =
        |path: &str, headers: &[(&str, &str)]| ipfs_plan(json!({ "ipfs": root }), path, headers);
    let head_photo = || doc.head("site-v1#12", "verified");
    let gw = |car: bool, changes: Value| json!({ "gateway": { "car": car }, "changes": changes });

    out.push(
        "ipfs/honest",
        "img/photo.jpg from site-v1 through a CAR, nothing changed: GatewayCore's answer",
        plan("/img/photo.jpg", &[]),
        "GET",
        gw(true, json!([])),
        complete(head_photo()?, doc.body("site-v1#12")?),
        None,
    );
    out.push(
        "ipfs/honest-raw",
        "the same through raw blocks, from a gateway the probe found without CARs",
        plan("/img/photo.jpg", &[]),
        "GET",
        gw(false, json!([])),
        complete(head_photo()?, doc.body("site-v1#12")?),
        None,
    );
    out.push(
        "ipfs/leaf-1-flipped",
        "the second leaf's byte 100 flipped in the CAR: the first leaf is released",
        plan("/img/photo.jpg", &[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "flip": { "cid": leaf1, "offset": 100 } }]),
        ),
        truncated(
            head_photo()?,
            content_body("ipfs-site-photo", 0, 262_144),
            "verification_failed",
            IPFS_FAILED,
        ),
        None,
    );
    out.push(
        "ipfs/leaf-0-flipped",
        "the first leaf flipped: nothing released",
        plan("/img/photo.jpg", &[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "flip": { "cid": leaf0, "offset": 100 } }]),
        ),
        truncated(
            head_photo()?,
            content_body("ipfs-site-photo", 0, 0),
            "verification_failed",
            IPFS_FAILED,
        ),
        None,
    );
    out.push(
        "ipfs/file-node-flipped",
        "the file's root node flipped: before the head",
        plan("/img/photo.jpg", &[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "flip": { "cid": photo_root, "offset": 10 } }]),
        ),
        error(502, IPFS_FAILED),
        None,
    );
    out.push(
        "ipfs/directory-flipped",
        "the site's root directory flipped",
        plan("/img/photo.jpg", &[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "flip": { "cid": root, "offset": 10 } }]),
        ),
        error(502, IPFS_FAILED),
        None,
    );
    out.push(
        "ipfs/raw-block-not-its-cid",
        "raw blocks only, the first leaf answered with the second's bytes",
        plan("/img/photo.jpg", &[]),
        "GET",
        gw(
            false,
            json!([{ "piece": "raw", "cid": leaf0, "as": leaf1 }]),
        ),
        truncated(
            head_photo()?,
            content_body("ipfs-site-photo", 0, 0),
            "verification_failed",
            IPFS_FAILED,
        ),
        None,
    );
    let hamt = dirs
        .iter()
        .find(|d| d["id"] == "hamt-v1")
        .ok_or("hamt-v1")?;
    let hamt_root = hamt["root"].as_str().ok_or("root")?;
    // A name whose path runs through a sub-shard, and that sub-shard.
    let root_block = B64.decode(
        doc.0["ipfs"]["blocks"][hamt_root]
            .as_str()
            .ok_or("root shard")?,
    )?;
    let root_node = crate::car::dag_pb(&root_block).ok_or("root shard isn't dag-pb")?;
    let (entry_name, shard) = (0..60)
        .map(|i| format!("entry-{i:03}.txt"))
        .find_map(|n| {
            let bucket = format!("{:02X}", crate::murmur3::hamt_bits(&n)[0]);
            root_node
                .links
                .iter()
                .find(|(_, l)| *l == bucket)
                .map(|(c, _)| (n, c.to_string()))
        })
        .ok_or("no name below a sub-shard")?;
    out.push(
        "ipfs/hamt-root-flipped",
        "the HAMT's root shard flipped",
        ipfs_plan(json!({ "ipfs": hamt_root }), &format!("/{entry_name}"), &[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "flip": { "cid": hamt_root, "offset": 10 } }]),
        ),
        error(502, IPFS_FAILED),
        None,
    );
    out.push(
        "ipfs/hamt-shard-flipped",
        "the sub-shard on the name's path flipped",
        ipfs_plan(json!({ "ipfs": hamt_root }), &format!("/{entry_name}"), &[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "flip": { "cid": shard, "offset": 10 } }]),
        ),
        error(502, IPFS_FAILED),
        None,
    );

    // Unhelpful but honest gateways.
    let big = "bafybeicts2tssv6avpna26sql26mlrowdhxwjpskl35ibnxdf7tf7cgo5a";
    let big_plan = |headers: &[(&str, &str)]| ipfs_plan(json!({ "ipfs": big }), "", headers);
    out.push("ipfs/car-ignores-entity-bytes", "a range from the second leaf; the CAR is the whole DAG: the first leaf isn't the block needed next, so the core cancels the CAR and fetches the rest raw", big_plan(&[("range", "bytes=262144-")]), "GET",
        gw(true, json!([{ "piece": "car", "answer": "whole_dag" }])),
        complete(doc.head("file-10485760-v1-balanced#13", "verified")?, doc.body("file-10485760-v1-balanced#13")?), None);
    out.push(
        "ipfs/car-no-duplicates",
        "a file whose one leaf is linked four times; the CAR sends it once and says dups=n, which the core doesn't take: every block is fetched raw",
        ipfs_plan(
            json!({ "ipfs": "bafybeiaw4srkelv2eyvj7r6x36d375tsptrlfzsvlxhidyj5me5huasve4" }),
            "",
            &[],
        ),
        "GET",
        gw(true, json!([{ "piece": "car", "answer": "no_dups" }])),
        complete(
            doc.head("file-repeat-v1#1", "verified")?,
            doc.body("file-repeat-v1#1")?,
        ),
        None,
    );
    out.push(
        "ipfs/car-no-duplicates-raw-leaf-wrong",
        "the dups=n CAR, honest, and the raw answer for the leaf another block's bytes: the core takes no block from the CAR, so the leaf the type's sniffing needs fails before the head. A core that read the CAR would answer 200",
        ipfs_plan(
            json!({ "ipfs": "bafybeiaw4srkelv2eyvj7r6x36d375tsptrlfzsvlxhidyj5me5huasve4" }),
            "",
            &[],
        ),
        "GET",
        gw(true, json!([
            { "piece": "car", "answer": "no_dups" },
            { "piece": "raw", "cid": "bafkreiaediwvfaybu3walxpbful7vqemyuqrqhr3uhndtg5zox7aw6fypq", "as": "bafybeiaw4srkelv2eyvj7r6x36d375tsptrlfzsvlxhidyj5me5huasve4" },
        ])),
        error(502, IPFS_FAILED),
        None,
    );
    out.push(
        "ipfs/car-no-duplicates-unannounced",
        "the same, its Content-Type still saying dups=y: the CAR ends cleanly before the walk does, which fetches the rest raw",
        ipfs_plan(
            json!({ "ipfs": "bafybeiaw4srkelv2eyvj7r6x36d375tsptrlfzsvlxhidyj5me5huasve4" }),
            "",
            &[],
        ),
        "GET",
        gw(true, json!([{ "piece": "car", "answer": "no_dups_unannounced" }])),
        complete(
            doc.head("file-repeat-v1#1", "verified")?,
            doc.body("file-repeat-v1#1")?,
        ),
        None,
    );
    out.push(
        "ipfs/car-reversed",
        "a CAR whose blocks come in reverse order",
        plan("/docs/page.html", &[]),
        "GET",
        gw(true, json!([{ "piece": "car", "answer": "reversed" }])),
        complete(doc.head("site-v1#8", "verified")?, doc.body("site-v1#8")?),
        None,
    );
    out.push(
        "ipfs/car-other-path",
        "a CAR that resolves the path to style.css instead of docs/page.html",
        plan("/docs/page.html", &[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "answer": { "path_as": "/style.css" } }]),
        ),
        complete(doc.head("site-v1#8", "verified")?, doc.body("site-v1#8")?),
        None,
    );
    out.push(
        "ipfs/car-early-end-marker",
        "the 10 MiB file's CAR ends after its root and four leaves, with boxo's truncation marker",
        big_plan(&[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "end_after_sections": 5, "marker": true }]),
        ),
        truncated(
            doc.head("file-10485760-v1-balanced#1", "verified")?,
            content_body("ipfs-file-10485760", 0, 4 * 262_144),
            "piece_failed",
            IPFS_STOPPED,
        ),
        None,
    );
    out.push(
        "ipfs/car-early-end",
        "the CAR ends inside its sixth section",
        big_plan(&[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "end_after_sections": 5, "end_inside": 100 }]),
        ),
        truncated(
            doc.head("file-10485760-v1-balanced#1", "verified")?,
            content_body("ipfs-file-10485760", 0, 4 * 262_144),
            "piece_failed",
            IPFS_STOPPED,
        ),
        None,
    );
    out.push(
        "ipfs/car-bad-header",
        "a CAR header with version 2",
        big_plan(&[]),
        "GET",
        gw(true, json!([{ "piece": "car", "header_version": 2 }])),
        error(502, IPFS_FAILED),
        None,
    );
    // The file has no extension and its root holds no bytes, so its type
    // is sniffed from the first leaf: framing that breaks before that
    // leaf is a failure before the head; after it, a truncation.
    let long_varint = [
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    ];
    let past_limit = [0x80, 0x80, 0xc0, 0x01];
    out.push("ipfs/car-long-varint", "after the root's section, a section length in 11 bytes: before the first leaf, which the type's sniffing needs, so before the head", big_plan(&[]), "GET",
        gw(true, json!([{ "piece": "car", "after_sections": 1, "insert": bytes(&long_varint) }])),
        error(502, IPFS_FAILED), None);
    out.push(
        "ipfs/car-section-past-limit",
        "after the root's section, a section length of 3 MiB: before the head, as car-long-varint",
        big_plan(&[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "after_sections": 1, "insert": bytes(&past_limit) }]),
        ),
        error(502, IPFS_FAILED),
        None,
    );
    out.push("ipfs/car-long-varint-after-sniff", "the 11-byte section length after the first leaf's section: the head went out on the first leaf's bytes, which are released, then the body is cut", big_plan(&[]), "GET",
        gw(true, json!([{ "piece": "car", "after_sections": 2, "insert": bytes(&long_varint) }])),
        truncated(doc.head("file-10485760-v1-balanced#1", "verified")?, content_body("ipfs-file-10485760", 0, 262_144), "verification_failed", IPFS_FAILED), None);
    out.push("ipfs/car-section-past-limit-after-sniff", "the 3 MiB section length after the first leaf's section: the first leaf released, then the body is cut", big_plan(&[]), "GET",
        gw(true, json!([{ "piece": "car", "after_sections": 2, "insert": bytes(&past_limit) }])),
        truncated(doc.head("file-10485760-v1-balanced#1", "verified")?, content_body("ipfs-file-10485760", 0, 262_144), "verification_failed", IPFS_FAILED), None);
    let blake3 = {
        let mh = multihash::Multihash::<64>::wrap(0x1e, &[0u8; 32])?;
        cid::Cid::new_v1(0x55, mh).to_string()
    };
    out.push(
        "ipfs/blake3-root",
        "a blake3 CID: unverifiable before anything is fetched",
        ipfs_plan(json!({ "ipfs": blake3 }), "", &[]),
        "GET",
        gw(true, json!([])),
        error(502, IPFS_UNVERIFIABLE),
        None,
    );
    out.push(
        "ipfs/piece-404",
        "the CAR answered 404 with a body of the gateway's own",
        plan("/img/photo.jpg", &[]),
        "GET",
        gw(
            true,
            json!([{ "piece": "car", "status": 404, "body": bytes(b"the gateway's own words") }]),
        ),
        error(404, IPFS_404),
        None,
    );
    out.push(
        "ipfs/name-not-found",
        "a name the verified directory doesn't hold: GatewayCore's 404, proven from the directory",
        plan("/missing", &[]),
        "GET",
        gw(true, json!([])),
        complete(doc.head("site-v1#29", "verified")?, doc.body("site-v1#29")?),
        None,
    );

    // IPNS.
    let recs = doc.0["ipfs"]["ipns"]["records"]
        .as_array()
        .ok_or("records")?;
    let rec = |id: &str| -> Result<Value, Err> {
        recs.iter()
            .find(|r| r["id"] == id)
            .map(|r| r["record"].clone())
            .ok_or_else(|| format!("record {id}").into())
    };
    let name = "k51qzi5uqu5dgyzs7wc9fb3dpul2l0yq1x1w2pi7ef703292ycquyorqqukz56";
    let ipns_plan = || ipfs_plan(json!({ "ipns": name }), "/", &[]);
    let head_ipns = || doc.head("ipns-ipns-ed25519-a#1", "latest_asserted");
    let serve = |r: Value| json!([{ "piece": "record", "name": name, "record": { "base64": r } }]);
    out.push(
        "ipns/honest",
        "an Ed25519-keyed name, its record of sequence 3",
        ipns_plan(),
        "GET",
        gw(true, serve(rec("ed25519-v2")?)),
        complete(head_ipns()?, doc.body("ipns-ipns-ed25519-a#1")?),
        None,
    );
    out.push(
        "ipns/other-key",
        "a record signed by another key",
        ipns_plan(),
        "GET",
        gw(true, serve(rec("ed25519-other-key")?)),
        error(502, IPFS_FAILED),
        None,
    );
    out.push(
        "ipns/expired",
        "an expired record",
        ipns_plan(),
        "GET",
        gw(true, serve(rec("ed25519-expired")?)),
        error(502, IPFS_FAILED),
        None,
    );
    let c_name = "k51qzi5uqu5dm4byyvx1rm820bmhg9pb9mbauoya4h97fj7y3281b68piobf5u";
    out.push(
        "ipns/value-names-dnslink",
        "a valid record whose value names a DNSLink name (/ipns/example.com): the walk can't follow it, and never falls back to an unverified fetch",
        ipfs_plan(json!({ "ipns": c_name }), "/", &[]),
        "GET",
        gw(true, json!([{ "piece": "record", "name": c_name, "record": { "base64": rec("ed25519-to-dnslink")? } }])),
        error(502, IPFS_UNVERIFIABLE),
        None,
    );
    out.0.push(json!({
        "id": "ipns/floor",
        "note": "one partition verifies sequence 5, then is served sequence 3, still valid: refused below the floor; another partition takes sequence 3",
        "deviation": "ipns-floor",
        "steps": [
            { "partition": "requests-floor", "plan": ipns_plan(), "method": "GET", "world": gw(true, serve(rec("ed25519-unknown")?)), "expect": complete(head_ipns()?, doc.body("ipns-ipns-ed25519-a#1")?) },
            { "partition": "requests-floor", "plan": ipns_plan(), "method": "GET", "world": gw(true, serve(rec("ed25519-v2")?)), "expect": error(502, IPFS_FAILED) },
            { "partition": "requests-floor-other", "plan": ipns_plan(), "method": "GET", "world": gw(true, serve(rec("ed25519-v2")?)), "expect": complete(head_ipns()?, doc.body("ipns-ipns-ed25519-a#1")?) },
        ],
    }));
    Ok(())
}

pub async fn build() -> Result<Value, Err> {
    let doc = Doc(serde_json::from_str(&std::fs::read_to_string(crate::OUT)?)?);
    let mut out = Cases(Vec::new());
    swarm(&doc, &mut out).await?;
    ipfs(&doc, &mut out)?;
    sizes(&mut out).await?;
    chains(&doc, &mut out).await?;
    Ok(Value::Array(out.0))
}

/// GatewayCore's error page, as `GatewayCore` writes one for `status`.
fn error_page(status: u16, reason: &str, detail: &str) -> (Value, Vec<u8>) {
    let page = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{status} {reason}</title><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head><body><main><h1>{reason}</h1><p>{detail}</p></main></body></html>"
    );
    let headers = json!([
        ["content-type", "text/html; charset=utf-8"],
        ["content-length", page.len().to_string()],
    ]);
    (headers, page.into_bytes())
}

/// The walk's `unixfs-sizes` rules (0009, Blocks and DAGs; Tests first):
/// files built here whose sizes disagree, which the honest gateway serves
/// beside dweb-verify.json's blocks (world.blocks). The native reader
/// slices a child by its declared size and serves them; the core cuts the
/// body as malformed where the sizes stop agreeing.
async fn sizes(out: &mut Cases) -> Result<(), Err> {
    use super::ipfs::{Unixfs, link, native_answer, pb_node, sha256_cid};
    use sha2::Digest;
    use std::collections::HashMap;
    const DAG_PB: u64 = 0x70;
    const RAW: u64 = 0x55;
    let file = |links: &[(&cid::Cid, u64)], filesize: u64, blocksizes: &[u64]| {
        let mut u = Unixfs::new(2);
        u.filesize = Some(filesize);
        u.blocksizes = blocksizes.to_vec();
        let links: Vec<_> = links.iter().map(|(c, t)| link(c, "", *t)).collect();
        pb_node(&links, Some(&u.encode()))
    };
    let a = content::bytes("checks-sizes-a", 1000);
    let b = content::bytes("checks-sizes-b", 1000);
    let c = content::bytes("checks-sizes-c", 999);
    let (la, lb, lc) = (
        sha256_cid(RAW, &a)?,
        sha256_cid(RAW, &b)?,
        sha256_cid(RAW, &c)?,
    );
    // A raw leaf longer than its entry: 1,000 bytes where 999 are declared.
    let leaf_root = file(&[(&la, 1000), (&lb, 1000)], 1999, &[1000, 999]);
    // A node whose filesize isn't its entry: 999 bytes where 1,000 are.
    let inner = file(&[(&lc, 999)], 999, &[999]);
    let li = sha256_cid(DAG_PB, &inner)?;
    let node_root = file(&[(&la, 1000), (&li, 1100)], 2000, &[1000, 1000]);
    // A root whose filesize isn't its content's sum: refused at the root.
    let sum_root = file(&[(&la, 1000), (&lb, 1000)], 2001, &[1000, 1000]);
    let mut held: HashMap<cid::Cid, Vec<u8>> = HashMap::new();
    for block in [&a, &b, &c] {
        held.insert(sha256_cid(RAW, block)?, block.clone());
    }
    held.insert(li, inner.clone());
    for (id, note, root, len, expect) in [
        (
            "ipfs/sizes-leaf-longer-than-entry",
            "a file over two raw leaves of 1,000 bytes whose blocksizes say 1,000 and 999: the first leaf is released, then the body is cut as malformed",
            &leaf_root,
            1999,
            true,
        ),
        (
            "ipfs/sizes-node-not-its-entry",
            "a file whose second child is a node of 999 bytes where its entry says 1,000: the first leaf is released, then the body is cut as malformed",
            &node_root,
            2000,
            true,
        ),
        (
            "ipfs/sizes-filesize-not-the-sum",
            "a file whose filesize, 2,001, isn't its blocksizes' sum, 2,000: malformed before the head",
            &sum_root,
            2001,
            false,
        ),
    ] {
        let rc = sha256_cid(DAG_PB, root)?;
        let mut blocks = held.clone();
        blocks.insert(rc, root.clone());
        let (status, headers, body) =
            native_answer(blocks.clone(), HashMap::new(), &format!("/ipfs/{rc}")).await?;
        // The native reader serves each, by the declared sizes.
        if status != 200 {
            return Err(format!("{id}: GatewayCore answers {status}").into());
        }
        let head = json!({
            "status": 200,
            "headers": [
                ["content-type", "application/octet-stream"],
                ["accept-ranges", "bytes"],
                ["content-length", len.to_string()],
                ["etag", format!("\"fi1:{rc}:.:{len}\"")],
                ["cache-control", "public, max-age=31536000, immutable"],
            ],
            "trust": { "name": null, "content": "verified" },
        });
        // Its head is the core's.
        let native_head: Vec<Value> = headers.iter().map(|(k, v)| json!([k, v])).collect();
        if expect && json!(native_head) != head["headers"] {
            return Err(format!("{id}: GatewayCore's head is {native_head:?}").into());
        }
        let expected = if expect {
            truncated(
                head,
                content_body("checks-sizes-a", 0, 1000),
                "malformed",
                IPFS_MALFORMED,
            )
        } else {
            error(502, IPFS_MALFORMED)
        };
        let world_blocks: serde_json::Map<String, Value> = blocks
            .iter()
            .map(|(c, b)| (c.to_string(), bytes(b)))
            .collect();
        for car in [true, false] {
            let id = if car {
                id.to_string()
            } else {
                format!("{id}-raw")
            };
            let note = if car {
                format!("{note}; through a CAR")
            } else {
                format!("{note}; through raw blocks")
            };
            out.push(
                &id,
                &note,
                ipfs_plan(json!({ "ipfs": rc.to_string() }), "", &[]),
                "GET",
                json!({ "gateway": { "car": car }, "blocks": world_blocks, "changes": [] }),
                expected.clone(),
                Some("unixfs-sizes"),
            );
            if let Some(case) = out.0.last_mut() {
                case["native"] = json!({
                    "status": status,
                    "length": body.len(),
                    "sha256": hex::encode(sha2::Sha256::digest(&body)),
                });
            }
        }
    }
    Ok(())
}

/// IPNS names that name names (0009, IPNS and DNSLink): GatewayCore
/// follows three, resolves a fourth and answers 400 whatever it names,
/// and asks for no fifth. The records are V2-only, signed by seeded
/// Ed25519 keys; the last names site-v1, as ipns/honest's does.
async fn chains(doc: &Doc, out: &mut Cases) -> Result<(), Err> {
    use super::ipfs::native_answer;
    use crate::ipns::{Key, Spec, record};
    use sha2::Digest;
    use std::collections::HashMap;
    let site = doc.0["ipfs"]["directories"]
        .as_array()
        .and_then(|d| d.iter().find(|d| d["id"] == "site-v1"))
        .ok_or("site-v1")?;
    let site_root = site["root"].as_str().ok_or("root")?.to_string();
    // GatewayCore's blocks: dweb-verify.json's, and the index document.
    let mut blocks: HashMap<cid::Cid, Vec<u8>> = HashMap::new();
    for (c, b) in doc.0["ipfs"]["blocks"].as_object().ok_or("blocks")? {
        blocks.insert(c.parse()?, B64.decode(b.as_str().ok_or("block")?)?);
    }
    let index = site["entries"]
        .as_array()
        .and_then(|e| e.iter().find(|e| e["path"] == "index.html"))
        .ok_or("index.html")?;
    blocks.insert(
        index["cid"].as_str().ok_or("cid")?.parse()?,
        index["text"].as_str().ok_or("text")?.as_bytes().to_vec(),
    );
    let (page_headers, page) = error_page(400, "Bad Request", "dnslink recursion limit exceeded");
    for (n, served, id, note) in [
        (
            3,
            3,
            "ipns/chain-3",
            "three names, each record naming the next, the last site-v1: served, as GatewayCore serves three resolutions",
        ),
        (
            4,
            4,
            "ipns/chain-4",
            "four names: GatewayCore resolves the fourth, then answers 400 whatever it names; the core does once the fourth record passes",
        ),
        (
            5,
            4,
            "ipns/chain-5",
            "five names, the fifth without a record: the same 400, the fifth never asked for",
        ),
    ] {
        let keys: Vec<Key> = (0..n)
            .map(|i| Key::ed25519(&format!("requests-chain-{n}-{i}")))
            .collect();
        let names = keys.iter().map(Key::name).collect::<Result<Vec<_>, _>>()?;
        let mut changes = Vec::new();
        let mut resolves = HashMap::new();
        for (i, key) in keys.iter().enumerate().take(served) {
            let value = match names.get(i + 1) {
                Some(next) => format!("/ipns/{next}"),
                None => format!("/ipfs/{site_root}"),
            };
            let r = record(&Spec::v2(&value, 1), key)?;
            changes.push(json!({ "piece": "record", "name": names[i], "record": bytes(&r) }));
            resolves.insert(names[i].clone(), value);
        }
        let path = format!("/ipns/{}/", names[0]);
        let (status, _, body) = native_answer(blocks.clone(), resolves, &path).await?;
        let expect = if n <= 3 {
            if status != 200 || B64.encode(&body) != doc.body("ipns-ipns-ed25519-a#1")?["base64"] {
                return Err(format!("{id}: GatewayCore answers {status}").into());
            }
            complete(
                doc.head("ipns-ipns-ed25519-a#1", "latest_asserted")?,
                doc.body("ipns-ipns-ed25519-a#1")?,
            )
        } else {
            if status != 400 || body != page {
                return Err(format!("{id}: GatewayCore answers {status}").into());
            }
            complete(
                json!({ "status": 400, "headers": page_headers, "trust": { "name": null, "content": "latest_asserted" } }),
                bytes(&page),
            )
        };
        out.push(
            id,
            note,
            ipfs_plan(json!({ "ipns": names[0] }), "/", &[]),
            "GET",
            json!({ "gateway": { "car": true }, "changes": changes }),
            expect,
            None,
        );
        if let Some(case) = out.0.last_mut() {
            case["native"] = json!({
                "status": status,
                "length": body.len(),
                "sha256": hex::encode(sha2::Sha256::digest(&body)),
            });
        }
    }
    Ok(())
}
