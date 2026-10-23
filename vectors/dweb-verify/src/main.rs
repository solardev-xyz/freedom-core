//! Records vectors/dweb-verify.json (design 0009, Tests first).
//!
//! `generate` writes the file; `check` records it again in memory and fails
//! unless it equals the committed one byte for byte. Run optimized:
//! `cargo run --release -- generate`.

mod bee;
mod content;
mod gateway;
mod mantaray;
mod node;
mod store;
mod swarm;

use serde_json::{Value, json};

const OUT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../dweb-verify.json");
const BEE_CHECK: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/bee-check/result.json");

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode != "generate" && mode != "check" {
        return Err("usage: dweb-verify-vectors generate | check".into());
    }
    let doc = json!({
        "meta": meta()?,
        "formats": formats(),
        "swarm": swarm::build().await?,
    });
    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    if mode == "generate" {
        std::fs::write(OUT, text)?;
        return Ok(());
    }
    let committed = std::fs::read_to_string(OUT)?;
    if committed != text {
        return Err("vectors/dweb-verify.json differs from what the generator records".into());
    }
    Ok(())
}

fn meta() -> Result<Value, Box<dyn std::error::Error>> {
    // The Bee cross-check's result, which bee-check/ writes by hand.
    let bee: Value = serde_json::from_str(&std::fs::read_to_string(BEE_CHECK)?)?;
    let results = bee["results"].as_array().cloned().unwrap_or_default();
    let differ: Vec<Value> = results
        .iter()
        .filter(|r| r["equal"] != true)
        .map(|r| json!({ "id": r["id"], "vector": r["vector"], "bee": r["bee"] }))
        .collect();
    Ok(json!({
        "generator": "vectors/dweb-verify (cargo run --release -- generate)",
        "design": "docs/design/0009-dweb-verification.md, Tests first",
        "ant": {
            "release": "v0.5.71",
            "commit": "910452d40762d7f0910b1d6848a6d9695b47d5c9",
            "crates": ["ant-control", "ant-crypto", "ant-gateway", "ant-retrieval"],
            "gateway": "ant-gateway's router (testkit::build_router), built as antd builds it: no CORS origins and light mode, as Freedom configures Ant",
            "node_loop": "a port of the node-loop arms these requests reach (ant-p2p src/behaviour.rs, same commit): GetChunkRaw, GetFeed, GetBytes, GetBytesEncrypted, run_stream_bytes and run_stream_bzz, over a memory chunk source, one attempt each (src/node.rs)",
            "missing_chunks": "a miss the network corroborated: FetchExhausted, not starved, with 8 not-found answers",
            "writers": "files: split_bytes_with_redundancy; manifests: build_single_file_manifest, build_collection_manifest, build_entries_manifest, build_feed_manifest; encrypted files: split_bytes_encrypted_with_keys; and, for shapes these can't make, the generator's own mantaray writer (src/mantaray.rs), held to Ant's on a manifest both write",
            "node_headers": {
                "names": ["server"],
                "note": "headers that describe the node, not the content: Ant's router adds `server: ant-gateway/0.5.71` to every answer",
            },
        },
        "bee_cross_check": {
            "bee": bee["bee"],
            "how": "bee-check/: Bee's pipeline splits each file's content at its redundancy level, and Bee's upload handlers' manifest code writes the single-file, directory and feed manifests (bzz.go fileUploadHandler, dirs.go storeDir, feed.go feedPostHandler); run by hand, not in CI",
            "compared": results.len(),
            "equal": results.len() - differ.len(),
            "differ": differ,
            "why_they_differ": "Ant's level-0 splitter wraps a level's lone leftover reference in an intermediate chunk of one reference, where Bee's hashtrie Sum carries it up unwrapped; the files marked lone_leaf_wrappers are Ant's trees, and their -bee cases are Bee's",
        },
        "request_headers": [
            ["swarm-chunk-retrieval-timeout", "30s"],
            ["swarm-redundancy-strategy", "3"],
            ["swarm-redundancy-fallback-mode", "true"],
        ],
        "clock_unix": swarm::CLOCK_UNIX,
    }))
}

fn formats() -> Value {
    json!({
        "content": "content(seed, n): SHA-256(seed ‖ u64_be(i)) for i = 0, 1, 2, …, concatenated and cut to n bytes. A file case's body is content(seed, size).",
        "key_stream": "key_stream(label): the chunk keys of an encrypted split, in Ant's chunk-write order; key i is keccak256(label ‖ u32_be(i)). Ant pads the ciphertext with zeros when keys are injected.",
        "owner_secret": "a feed owner's secp256k1 secret is keccak256(label), the label given with the feed.",
        "chunks": "address (hex) → wire bytes (base64), for every chunk a reader needs that isn't a slice of some content: roots, intermediates, the wrappers Ant's splitter writes, manifest nodes, feed updates, encrypted chunks and the crafted shapes. A data leaf is rebuilt from its content: leaf i of a file of n bytes is u64_le(len) ‖ content[i·4096 .. min(n, (i+1)·4096)]. Parity chunks are left out: nothing reads them when nothing is missing.",
        "files": "data trees from Ant's splitter, one per size and redundancy level: id, seed, size, redundancy, root, tree (the addresses Ant's joiner reads for the whole body, less the content's leaves, root first), data_leaves, parities (chunks the split wrote that the join doesn't read), joined_equals_content (whether Ant's joiner reads the tree back as the content), and lone_leaf_wrappers where Ant's tree has them. A -bee case is the same content split as Bee splits it, where that differs.",
        "manifests": "id, root, writer, nodes (the chunks of the manifest's nodes), entries, and lookups: ant-retrieval's lookup_path answer for each path, the resolved data_ref, content_type, metadata and feed, or the error's text.",
        "feeds": "sequence feeds: owner, topic, manifest (build_feed_manifest), manifest_nodes, and updates (index, address, id, version, and the reference or root the update names). v1 updates wrap u64_be(timestamp) ‖ reference, timestamps counted from meta.clock_unix; v2 updates wrap the root chunk itself.",
        "shapes": "trees Ant reads that a simple reader wouldn't, each a root over two leaves whose second leaf's span or payload differs from the 60 bytes its parent gives it.",
        "exchanges": "requests through Ant's gateway and its answers: id (case#n), case, note, request (method, path, headers; every bzz request carries meta.request_headers), response (status, headers in Ant's order, and body). A body is {length: 0}, {content: {seed, from, length}} for a slice of content(seed, …), {base64} up to 64 KiB, or {length, sha256}. A multipart boundary, which Ant draws at random, is written {boundary} in the header and the body.",
    })
}
