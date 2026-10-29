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

pub fn build() -> Result<Value, Err> {
    crate::murmur3::self_check()?;
    Ok(json!({
        "meta": {
            "generator": "vectors/dweb-verify (cargo run --release -- cases; generate and check include it)",
            "design": "docs/design/0009-dweb-verification.md, Tests first: the adversarial vectors, as checks on single pieces",
            "source": "design: each case's expect is the design's, written by hand in src/cases/; the generator lays out and signs the bytes and checks each case's shape",
            "oracles": {
                "ant": "Ant v0.5.71 (910452d): ant_crypto::cac_valid and soc_valid on the same bytes",
                "native": "freedom-ipfs e7dcc6f, the commit freedom-ipfsd pins: freedom_ipfs_core::verify_block, parse_car_v1 (its whole-buffer CAR parser, which checks no block) and freedom_ipfs_namesys::verify_ipns_record on the same bytes. In this generator's graph, libp2p-identity also has its ecdsa and secp256k1 features (through Ant's libp2p), which freedom-ipfsd's doesn't: for an ECDSA key the generator's build checks the signature where freedom-ipfsd's fails to decode the key. Both refuse the case here",
            },
            "clock_unix": crate::swarm::CLOCK_UNIX,
        },
        "formats": formats(),
        "swarm": swarm::build()?,
        "ipfs": ipfs::build()?,
        "ipns": ipns::build()?,
    }))
}

fn formats() -> Value {
    json!({
        "bytes": "{base64}; or, for bytes past 64 KiB, {parts, length, sha256}: the parts concatenated, each {base64}, {zeros: n} or {repeat: {base64, count}}",
        "expect": "{ok: {…}} with what the check yields, or {fail: code}. Codes, as 0009's Failures names them: verification_failed (the bytes aren't what their address, CID or signature commits to, or the framing around them is broken), unverifiable (authentic, or possibly so, but outside what the core checks: a single-owner chunk off the feed path, an encrypted reference, an unsupported hash, structure past the decoders' caps), malformed (authentic content that can't be decoded or is inconsistent)",
        "oracles": "ant and native record the pinned nodes' own verdict on the same bytes. Where it differs from expect, the case names the deviation (0009, Parity)",
        "swarm_chunks": "a piece fetched as /chunks/<address> where the walk needs a content-addressed chunk (a root, a manifest node, an intermediate chunk, or a leaf's fallback): address, wire, expect {ok: {span_hex, payload_length}} or {fail}. span_hex is the wire's 8-byte span as sent (little-endian, the level byte included)",
        "swarm_feed_updates": "a piece fetched as /chunks/<address> where the walk computed a feed update's address: owner, topic, index, address (keccak256(keccak256(topic ‖ u64_be(index)) ‖ owner)), wire, expect {ok: {version: v1, timestamp, reference}} or {ok: {version: v2, root, span_hex, payload_length}}, or {fail}",
        "swarm_leaves": "a leaf in a /bytes stream: address (as its parent names it), logical_length (from the parent's geometry), streamed (the stream's bytes for it), chunk (the wire /chunks/<address> answers, read only when the streamed bytes don't hash to the address), expect {ok: {fallback}} or {fail, fallback}; fallback says whether /chunks was read",
        "ipfs_blocks": "a block as a CAR section or a raw block brings it: cid, block, expect {ok: {codec}} or {fail}",
        "ipfs_dag_pb": "a block that passed its CID, decoded as dag-pb: cid, block, expect {ok: {links: [{hash, name, tsize}], data}} or {fail}; data is the Data field's bytes or null",
        "ipfs_unixfs": "a dag-pb node's Data decoded as UnixFS, checked against its links where it is a file: cid, block, expect {ok: {type, filesize, blocksizes, data_length}} or {fail}",
        "ipfs_hamt": "a name's lookup in dweb-verify.json's HAMT (ipfs.directories, hamt-v1; its shards are in ipfs.blocks): root, name, hash_bits (the first 64 bits of MurmurHash3 x64 128 of the name, seed 0, big-endian; a byte per level), levels (per shard: depth, bucket, and the link named by the bucket's two uppercase hex digits, alone for a sub-shard or followed by the name for an entry, or null), expect {ok: {cid}} or {absent: true}. The generator checks every name against Kubo's own layout",
        "ipfs_car": "a CAR body: car, expect {ok: {sections: [cid]}} when it reads to its end at a section boundary; {fail, after: k}, k the sections read whole before the failure; or {ended: {after: k}} when the stream ends inside a section, an early end the walk takes as a piece failure. Whether the walk then has what it needs is the walk's question, not the reader's",
        "ipns_records": "an IPNS record as /ipns/<name>?format=ipns-record answers it: name, record, now (unix seconds), expect {ok: {value, sequence, validity, ttl_ns}} or {fail}",
    })
}
