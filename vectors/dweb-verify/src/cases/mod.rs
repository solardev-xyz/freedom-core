//! Records vectors/dweb-verify-cases.json: design 0009's own cases (Tests
//! first), beside the node-recorded vectors/dweb-verify.json.
//!
//! Every `expect` here is the design's, written out by hand in these
//! modules. The generator only lays the bytes out (mutations, crafted
//! chunks, blocks and records, signatures), and checks each case's shape:
//! the honest bytes a case changes pass, its change is the only one, and the
//! pinned nodes' own checks (`ant`, `native`), recorded beside each case,
//! agree with `expect` wherever no deviation is named.

mod ipfs;
mod ipns;
mod requests;
mod swarm;

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub type Err = Box<dyn std::error::Error>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Bytes up to this length are written whole; longer ones as parts.
const INLINE_MAX: usize = 64 * 1024;

/// Bytes as the cases file writes them: `{base64}`, or, past 64 KiB,
/// `{parts, length, sha256}`, each part `{base64}`, `{zeros: n}` or
/// `{repeat: {base64, count}}`, concatenated.
pub fn bytes(b: &[u8]) -> Value {
    if b.len() <= INLINE_MAX {
        return json!({ "base64": B64.encode(b) });
    }
    json!({
        "parts": [{ "base64": B64.encode(b) }],
        "length": b.len(),
        "sha256": hex::encode(Sha256::digest(b)),
    })
}

/// A long byte string from its parts, so the file stays small. Each part is
/// `(prefix, unit, count)`: `prefix` once, then `unit` repeated `count` times.
pub fn parts(segments: &[(&[u8], &[u8], usize)]) -> (Vec<u8>, Value) {
    let mut out = Vec::new();
    let mut desc = Vec::new();
    for (prefix, unit, count) in segments {
        if !prefix.is_empty() {
            out.extend_from_slice(prefix);
            desc.push(json!({ "base64": B64.encode(prefix) }));
        }
        if *count > 0 && !unit.is_empty() {
            for _ in 0..*count {
                out.extend_from_slice(unit);
            }
            if unit.iter().all(|&b| b == 0) {
                desc.push(json!({ "zeros": unit.len() * count }));
            } else {
                desc.push(json!({ "repeat": { "base64": B64.encode(unit), "count": count } }));
            }
        }
    }
    let value = if out.len() <= INLINE_MAX {
        json!({ "base64": B64.encode(&out) })
    } else {
        json!({ "parts": desc, "length": out.len(), "sha256": hex::encode(Sha256::digest(&out)) })
    };
    (out, value)
}

pub fn ok(v: Value) -> Value {
    json!({ "ok": v })
}

pub fn fail(code: &str) -> Value {
    json!({ "fail": code })
}

pub async fn build() -> Result<Value, Err> {
    crate::murmur3::self_check()?;
    Ok(json!({
        "meta": {
            "generator": "vectors/dweb-verify (cargo run --release -- cases; generate and check include it)",
            "design": "docs/design/0009-dweb-verification.md, Tests first: the adversarial vectors, as checks on single pieces",
            "source": "design: each case's expect is the design's, written by hand in src/cases/; the generator lays out and signs the bytes and checks each case's shape",
            "oracles": {
                "ant": "Ant v0.5.71 (910452d): ant_crypto::cac_valid and soc_valid on the same bytes; for an intermediate chunk, ant_retrieval::join over its children; for a manifest node, ant_retrieval::lookup_path over the node stored as a file",
                "native": "freedom-ipfs e7dcc6f, the commit freedom-ipfsd pins: freedom_ipfs_core::verify_block, parse_car_v1 (its whole-buffer CAR parser, which checks each block and doesn't read the header) and freedom_ipfs_namesys::verify_ipns_record on the same bytes, and GatewayCore over a memory provider for a HAMT lookup. In this generator's graph, libp2p-identity also has its ecdsa and secp256k1 features (through Ant's libp2p), which freedom-ipfsd's doesn't: the ECDSA record, validly signed, passes this build's check, which shows it otherwise valid, where freedom-ipfsd's fails to decode the key; the design refuses it as unverifiable",
            },
            "clock_unix": crate::swarm::CLOCK_UNIX,
        },
        "formats": formats(),
        "swarm": swarm::build().await?,
        "ipfs": ipfs::build().await?,
        "ipns": ipns::build()?,
        "requests": requests::build()?,
    }))
}

fn formats() -> Value {
    json!({
        "bytes": "{base64}; or, for bytes past 64 KiB, {parts, length, sha256}: the parts concatenated, each {base64}, {zeros: n} or {repeat: {base64, count}}",
        "expect": "{ok: {…}} with what the check yields, or {fail: code}. Codes, as 0009's Failures names them: verification_failed (the bytes aren't what their address, CID or signature commits to, or the framing around them is broken), unverifiable (authentic, or possibly so, but outside what the core checks: a single-owner chunk off the feed path, an encrypted reference, an unsupported hash, structure past the decoders' caps), malformed (authentic content that can't be decoded or is inconsistent)",
        "oracles": "ant and native record the pinned nodes' own verdict on the same bytes. Where it differs from expect, the case names the deviation (0009, Parity)",
        "swarm_chunks": "a piece fetched as /chunks/<address> where the walk needs a content-addressed chunk (a root, a manifest node, an intermediate chunk, or a leaf's fallback): address, wire, expect {ok: {span_hex, payload_length}} or {fail}. span_hex is the wire's 8-byte span as sent (little-endian, the level byte included)",
        "swarm_feed_updates": "a piece fetched as /chunks/<address> where the walk computed a feed update's address: owner, topic, index, address (keccak256(keccak256(topic ‖ u64_be(index)) ‖ owner)), wire, expect {ok: {version: v1, timestamp, reference}} or {ok: {version: v2, root, span_hex, payload_length}}, or {fail}",
        "swarm_intermediates": "a chunk that passed its address check, read as an intermediate node of logical_length bytes (its own span's value): address, wire, logical_length, expect {ok: {level, data_references, parities, children: [{address, length}]}} or {fail}. level is the span's top byte less 0x80 when that byte is past 128, else 0; parities are Bee's count for the span at that level (none at level 0); children are the data references after the trailing all-zero ones are dropped and before the parities, each with the length the design's geometry gives it",
        "swarm_manifest_nodes": "a mantaray node's joined bytes (node), decoded: expect {ok: {manifest: true, ref_size, entry, forks: [{byte, type, prefix, child, metadata}]}} with prefix, child and entry in hex and metadata only the keys the walk reads (Content-Type, Filename, website-index-document, website-error-document, swarm-feed-owner, swarm-feed-topic, swarm-feed-type), the last value of a repeated key; {ok: {manifest: false}} for bytes without a version hash; or {fail}: malformed for a node Ant refuses, unverifiable past the core's 1 MiB (deviation manifest-node-cap). ant records Ant's decoding (parsed, malformed or not_a_manifest) and the fork paths it looked up, each agreeing",
        "swarm_leaves": "a leaf in a /bytes stream: address (as its parent names it), logical_length (from the parent's geometry), streamed (the stream's bytes for it), chunk (the wire /chunks/<address> answers, read only when the streamed bytes don't hash to the address), expect {ok: {fallback}} or {fail, fallback}; fallback says whether /chunks was read",
        "ipfs_blocks": "a block as a CAR section or a raw block brings it: cid, block, expect {ok: {codec}} or {fail}",
        "ipfs_dag_pb": "a block that passed its CID, decoded as dag-pb: cid, block, expect {ok: {links: [{hash, name, tsize}], data}} or {fail}; data is the Data field's bytes or null",
        "ipfs_unixfs": "a dag-pb node's Data decoded as UnixFS, checked against its links where it is a file: cid, block, expect {ok: {type, filesize, blocksizes, data_length}} or {fail}",
        "ipfs_hamt": "a name's lookup in dweb-verify.json's HAMT (ipfs.directories, hamt-v1; its shards are in ipfs.blocks): root, name, hash_bits (the first 64 bits of MurmurHash3 x64 128 of the name, seed 0, big-endian; a byte per level), levels (per shard: depth, bucket, and the link named by the bucket's two uppercase hex digits, alone for a sub-shard or followed by the name for an entry, or null), expect {ok: {cid}} or {absent: true}. The generator checks every name against Kubo's own layout. A case with blocks carries its own root shard (cid → base64), rebuilt from hamt-v1's with an entry out of its place (deviation hamt-lookup), and native is GatewayCore's answer for /ipfs/<root>/<name>",
        "ipfs_car": "a CAR body: car, expect {ok: {sections: [cid]}} when it reads to its end at a section boundary; {fail, after: k}, k the sections read whole before the failure; or {ended: {after: k}} when the stream ends inside a section, an early end the walk takes as a piece failure. Whether the walk then has what it needs is the walk's question, not the reader's",
        "requests": "whole requests through the verifier: id, note, plan (the verify plan's node, root, path, query and headers; its retry, timers, response and trust are the backend's, as dweb.open writes them), method, partition (null: the profile's), world, expect, and deviation where the design differs from the bundled node. A case with steps runs each step ({partition, plan, method, world, expect}) in order on one verifier, so what one step leaves in a partition (the structure cache, IPNS floors) meets the next",
        "requests_world": "the node the verifier's pieces reach: the honest node of dweb-verify.json, with the case's own chunks (chunks: address → bytes), and changes applied to the pieces they name. The honest Ant answers /chunks/<address> with 200 and the chunk's wire (dweb-verify.json's swarm.chunks, the case's chunks, or a data leaf rebuilt from its content), or 404; /bytes/<reference> with the file's bytes, as Ant's joiner reads them, 206 with exactly the requested single range and Content-Range bytes a-b/size, or 200 whole without one; /feeds/<owner>/<topic> with 200 and swarm-feed-index, the latest update's index in 16 hex digits. The honest gateway (gateway.car: whether the probe found CARs; false means every block is fetched raw) answers a CAR request as a conforming trustless gateway does (the path's blocks root first, then the entity, depth-first with duplicates, only the blocks covering entity-bytes; ipfs.kubo holds Kubo's answers, which it must reproduce), a raw block request with the block, a record request with the change's record. Retries happen in main: a status in a world is the piece's final answer",
        "requests_changes": "a world's changes: each names its piece and what differs. chunk {address}: flip (wire offset, the byte XORed with 1), wire (bytes answered instead), or status and body. bytes {reference}: flip (file offset, in whatever the stream carries), answer whole (200 with the whole file, Range ignored), answer at_zero (200 holding the range's bytes at offset 0, and nothing else), end_after (the body ends after n bytes), content_range (the 206 names this instead), stall_after (n bytes, then nothing: main's body idle timer ends the piece), body (bytes answered as an exact 206). car: flip {cid, offset} (that block, wherever a CAR carries it), answer whole_dag (the whole DAG, entity-bytes ignored), no_dups (each block once, its Content-Type saying dups=n), no_dups_unannounced (each block once, its Content-Type still saying dups=y), reversed (the blocks in reverse order), {path_as} (the path resolved as another), end_after_sections (n whole sections, then the end, with boxo's marker when marker is true, or end_inside bytes of the next section), header_version (the header's version), after_sections and insert (bytes inserted after n sections), or status and body. raw {cid}: as (another block's bytes), or status and body. record {name}: record (the bytes answered)",
        "requests_expect": "a request's expect, what the page gets. {head, body}: the head (status, headers, and trust {name, content}; from names the bundled node's answer it copies, less meta.ant.node_headers) and the whole body. {error: {status, body}}: before the head, the core's {code, message} with that status. {head, truncated: {released, abort: {code, message}}}: the head, then exactly the released bytes, then the core's abort. Bodies are as dweb-verify.json's exchanges write them. Every case also ends with the request's reservations back at zero",
        "ipns_records": "an IPNS record as /ipns/<name>?format=ipns-record answers it: name, record, now (unix seconds), expect {ok: {value, sequence, validity, ttl_ns}} or {fail}",
    })
}
