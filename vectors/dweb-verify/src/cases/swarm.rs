//! Swarm piece checks: content-addressed chunks, feed updates and leaves
//! (0009, Chunks, Manifests and feeds, Leaves).

use super::{Err, bytes, fail, ok};
use crate::content;
use crate::store::MemFetcher;
use ant_crypto::keccak256;
use k256::elliptic_curve::PrimeField;
use serde_json::{Value, json};
use std::collections::HashMap;

type Addr = [u8; 32];

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn cac(span: [u8; 8], payload: &[u8]) -> Result<(Addr, Vec<u8>), Err> {
    let addr = ant_crypto::bmt_hash_with_span(&span, payload).ok_or("payload past 4096 bytes")?;
    let mut wire = span.to_vec();
    wire.extend_from_slice(payload);
    Ok((addr, wire))
}

fn span(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

fn secret(label: &str) -> [u8; 32] {
    keccak256(label.as_bytes())
}

fn owner(secret: &[u8; 32]) -> Result<[u8; 20], Err> {
    let sk = k256::ecdsa::SigningKey::from_bytes(secret.into()).map_err(|e| e.to_string())?;
    Ok(ant_crypto::ethereum_address_from_public_key(
        sk.verifying_key(),
    ))
}

fn soc_address(id: &Addr, owner: &[u8; 20]) -> Addr {
    let mut input = id.to_vec();
    input.extend_from_slice(owner);
    keccak256(&input)
}

fn feed_id(topic: &Addr, index: u64) -> Addr {
    let mut input = topic.to_vec();
    input.extend_from_slice(&index.to_be_bytes());
    keccak256(&input)
}

/// A single-owner chunk: `id ‖ signature ‖ inner wire`, the signature over
/// the EIP-191 digest of `keccak256(id ‖ inner address)`, as Bee signs.
fn soc(secret: &[u8; 32], id: &Addr, inner: &[u8]) -> Result<Vec<u8>, Err> {
    let inner_addr = inner_address(inner)?;
    let mut sig_data = id.to_vec();
    sig_data.extend_from_slice(&inner_addr);
    let sig = ant_crypto::sign_handshake_data(secret, &keccak256(&sig_data))
        .map_err(|e| e.to_string())?;
    let mut wire = id.to_vec();
    wire.extend_from_slice(&sig);
    wire.extend_from_slice(inner);
    Ok(wire)
}

fn inner_address(inner: &[u8]) -> Result<Addr, Err> {
    let s: [u8; 8] = inner
        .get(..8)
        .ok_or("inner chunk shorter than a span")?
        .try_into()?;
    Ok(ant_crypto::bmt_hash_with_span(&s, &inner[8..]).ok_or("inner payload past 4096")?)
}

fn flip(b: &[u8], at: usize) -> Vec<u8> {
    let mut v = b.to_vec();
    v[at] ^= 0x01;
    v
}

fn oracle(address: &Addr, wire: &[u8]) -> Value {
    json!({
        "cac_valid": ant_crypto::cac_valid(address, wire),
        "soc_valid": ant_crypto::soc_valid(address, wire),
    })
}

struct Cases(Vec<Value>);

impl Cases {
    fn chunk(
        &mut self,
        id: &str,
        note: &str,
        address: &Addr,
        wire: &[u8],
        expect: Value,
    ) -> Result<(), Err> {
        let ant = oracle(address, wire);
        // The design's verdict is Ant's, except that a valid SOC where a CAC
        // is needed is unverifiable (deviation soc-references), not followed.
        let agrees = match (expect.get("ok"), expect["fail"].as_str()) {
            (Some(_), _) => ant["cac_valid"] == true,
            (None, Some("unverifiable")) => ant["soc_valid"] == true && ant["cac_valid"] == false,
            (None, Some(_)) => ant["cac_valid"] == false && ant["soc_valid"] == false,
            _ => false,
        };
        if !agrees {
            return Err(format!("chunk case {id}: Ant's checks {ant} don't fit {expect}").into());
        }
        let mut case = json!({
            "id": id,
            "note": note,
            "address": h(address),
            "wire": bytes(wire),
            "expect": expect,
            "ant": ant,
        });
        if case["expect"]["fail"] == "unverifiable" {
            case["deviation"] = json!("soc-references");
        }
        self.0.push(case);
        Ok(())
    }
}

fn chunk_ok(wire: &[u8]) -> Value {
    ok(json!({ "span_hex": h(&wire[..8]), "payload_length": wire.len() - 8 }))
}

fn chunks() -> Result<Vec<Value>, Err> {
    let mut c = Cases(Vec::new());
    let (empty, empty_w) = cac(span(0), &[])?;
    c.chunk(
        "empty",
        "span 0 and no payload: the empty chunk, also an empty file's reference",
        &empty,
        &empty_w,
        chunk_ok(&empty_w),
    )?;
    let (bare, bare_w) = cac(span(4096), &[])?;
    c.chunk(
        "span-without-payload",
        "span 4096 and no payload: neither node compares the span with the payload's length",
        &bare,
        &bare_w,
        chunk_ok(&bare_w),
    )?;
    let full = content::bytes("checks-leaf-full", 4096);
    let (full_a, full_w) = cac(span(4096), &full)?;
    c.chunk(
        "leaf-4096",
        "a full leaf",
        &full_a,
        &full_w,
        chunk_ok(&full_w),
    )?;
    let short = content::bytes("checks-leaf-short", 100);
    let (short_a, short_w) = cac(span(100), &short)?;
    c.chunk(
        "leaf-100",
        "a short leaf",
        &short_a,
        &short_w,
        chunk_ok(&short_w),
    )?;
    let other = content::bytes("checks-leaf-other", 4096);
    let (other_a, _) = cac(span(4096), &other)?;
    let mut refs = full_a.to_vec();
    refs.extend_from_slice(&other_a);
    let (inter, inter_w) = cac(span(8192), &refs)?;
    c.chunk(
        "intermediate",
        "span 8192 over two leaves' references",
        &inter,
        &inter_w,
        chunk_ok(&inter_w),
    )?;
    let mut level = span(8192);
    level[7] = 0x81;
    let (lvl, lvl_w) = cac(level, &refs)?;
    c.chunk("intermediate-level-byte", "an erasure-coded intermediate's span, its top byte 0x81 (level 1): the address commits to the span as sent", &lvl, &lvl_w, chunk_ok(&lvl_w))?;
    let mut ext = short_w.clone();
    ext.push(0);
    c.chunk("zero-extended", "leaf-100 with one zero byte appended: the BMT pads the payload with zeros, so the address is the same and the chunk is valid with 101 payload bytes", &short_a, &ext, chunk_ok(&ext))?;
    let mut padded = short_w.clone();
    padded.resize(8 + 4096, 0);
    c.chunk(
        "zero-padded-to-4096",
        "leaf-100 padded with zeros to 4096 bytes: the same address",
        &short_a,
        &padded,
        chunk_ok(&padded),
    )?;
    c.chunk(
        "flipped-payload",
        "leaf-100 with payload byte 50 flipped",
        &short_a,
        &flip(&short_w, 8 + 50),
        fail("verification_failed"),
    )?;
    c.chunk(
        "flipped-span",
        "leaf-100 with its span's first byte flipped",
        &short_a,
        &flip(&short_w, 0),
        fail("verification_failed"),
    )?;
    let mut over = full_w.clone();
    over.push(0);
    c.chunk(
        "payload-4097",
        "leaf-4096 with a 4097th payload byte (zero): past the chunk size, so no address matches",
        &full_a,
        &over,
        fail("verification_failed"),
    )?;
    c.chunk(
        "shorter-than-span",
        "7 bytes: shorter than a span",
        &empty,
        &[0u8; 7],
        fail("verification_failed"),
    )?;
    c.chunk(
        "other-chunk",
        "leaf-4096's wire at leaf-100's address",
        &short_a,
        &full_w,
        fail("verification_failed"),
    )?;
    let s = secret("checks-soc-owner");
    let id = keccak256(b"checks-soc-id");
    let soc_a = soc_address(&id, &owner(&s)?);
    let soc1 = soc(&s, &id, &short_w)?;
    c.chunk("soc", "a valid single-owner chunk at its own address, wrapping leaf-100, where a content-addressed chunk is needed", &soc_a, &soc1, fail("unverifiable"))?;
    let soc2 = soc(&s, &id, &full_w)?;
    c.chunk(
        "soc-same-address-other-payload",
        "the same owner and identifier wrapping leaf-4096 instead: the same address, other content",
        &soc_a,
        &soc2,
        fail("unverifiable"),
    )?;
    let replicas = ant_crypto::soc::REPLICAS_OWNER_SECRET;
    let mut rid = short_a;
    rid[0] = 0x00;
    let rsoc = soc(&replicas, &rid, &short_w)?;
    let raddr = soc_address(&rid, &owner(&replicas)?);
    c.chunk("soc-replicas-owner", "a dispersed replica: signed by the published replicas key, its identifier past the first byte equal to the wrapped chunk's address", &raddr, &rsoc, fail("unverifiable"))?;
    c.chunk(
        "soc-bad-signature",
        "soc with a signature byte flipped: neither a valid CAC nor a valid SOC",
        &soc_a,
        &flip(&soc1, 40),
        fail("verification_failed"),
    )?;
    Ok(c.0)
}

struct Feed {
    secret: [u8; 32],
    owner: [u8; 20],
    topic: Addr,
}

fn feed_case(
    id: &str,
    note: &str,
    f: &Feed,
    index: u64,
    wire: &[u8],
    expect: Value,
) -> Result<Value, Err> {
    let address = soc_address(&feed_id(&f.topic, index), &f.owner);
    let valid = ant_crypto::soc_valid(&address, wire);
    let want = expect.get("ok").is_some() || expect["fail"] == "unverifiable";
    if valid != want {
        return Err(format!("feed case {id}: Ant's soc_valid is {valid}").into());
    }
    Ok(json!({
        "id": id,
        "note": note,
        "owner": h(&f.owner),
        "topic": h(&f.topic),
        "index": index,
        "address": h(&address),
        "wire": bytes(wire),
        "expect": expect,
        "ant": { "soc_valid": valid },
    }))
}

/// `r ‖ s ‖ v` with `s` replaced by `n − s` and the recovery bit flipped:
/// the same signature, mathematically, in its high-s form.
fn high_s(sig: &[u8]) -> Result<Vec<u8>, Err> {
    let s_bytes: [u8; 32] = sig[32..64].try_into()?;
    let s = Option::<k256::Scalar>::from(k256::Scalar::from_repr(s_bytes.into()))
        .ok_or("s isn't a scalar")?;
    let neg = -s;
    let mut out = sig.to_vec();
    out[32..64].copy_from_slice(&neg.to_bytes());
    out[64] = if sig[64] == 27 { 28 } else { 27 };
    Ok(out)
}

fn feed_updates() -> Result<Vec<Value>, Err> {
    let s = secret("checks-feed-owner");
    let f = Feed {
        secret: s,
        owner: owner(&s)?,
        topic: keccak256(b"checks-feed-topic"),
    };
    let mut out = Vec::new();
    let (site, _) = cac(span(4096), &content::bytes("checks-feed-target", 4096))?;
    let ts: u64 = crate::swarm::CLOCK_UNIX;
    let mut v1 = ts.to_be_bytes().to_vec();
    v1.extend_from_slice(&site);
    let (_, v1_inner) = cac(span(40), &v1)?;
    let id0 = feed_id(&f.topic, 0);
    let w_v1 = soc(&f.secret, &id0, &v1_inner)?;
    out.push(feed_case(
        "v1",
        "a v1 update: it wraps 40 bytes, u64_be(timestamp) ‖ reference",
        &f,
        0,
        &w_v1,
        ok(json!({ "version": "v1", "timestamp": ts, "reference": h(&site) })),
    )?);
    let leaf = content::bytes("checks-feed-leaf", 100);
    let (leaf_a, leaf_w) = cac(span(100), &leaf)?;
    let w_v2 = soc(&f.secret, &id0, &leaf_w)?;
    out.push(feed_case("v2-leaf", "a v2 update wrapping a 100-byte file's root chunk", &f, 0, &w_v2,
        ok(json!({ "version": "v2", "root": h(&leaf_a), "span_hex": h(&leaf_w[..8]), "payload_length": 100 })))?);
    let a = content::bytes("checks-feed-a", 4096);
    let b = content::bytes("checks-feed-b", 4096);
    let (aa, _) = cac(span(4096), &a)?;
    let (ba, _) = cac(span(4096), &b)?;
    let mut refs = aa.to_vec();
    refs.extend_from_slice(&ba);
    let (root, root_w) = cac(span(8192), &refs)?;
    let w_tree = soc(&f.secret, &id0, &root_w)?;
    out.push(feed_case("v2-intermediate", "a v2 update wrapping an 8192-byte file's root, an intermediate chunk", &f, 0, &w_tree,
        ok(json!({ "version": "v2", "root": h(&root), "span_hex": h(&root_w[..8]), "payload_length": 64 })))?);
    let mut forty = 1u64.to_be_bytes().to_vec();
    forty.extend_from_slice(&content::bytes("checks-feed-forty", 32));
    let (_, forty_w) = cac(span(40), &forty)?;
    let w_amb = soc(&f.secret, &id0, &forty_w)?;
    out.push(feed_case("v2-of-v1-length", "a v2 update whose root chunk has a 40-byte payload: v1's length, so it is read as v1, as Ant tries v1 first (its reference must then load, a request-level check)", &f, 0, &w_amb,
        ok(json!({ "version": "v1", "timestamp": u64::from_be_bytes(forty[..8].try_into()?), "reference": h(&forty[8..]) })))?);
    let mut enc = ts.to_be_bytes().to_vec();
    enc.extend_from_slice(&site);
    enc.extend_from_slice(&keccak256(b"checks-feed-key"));
    let (_, enc_inner) = cac(span(72), &enc)?;
    let w_enc = soc(&f.secret, &id0, &enc_inner)?;
    out.push(feed_case("v1-encrypted", "a v1 update of 72 bytes: its reference is 64 bytes, encrypted, which the walk doesn't follow", &f, 0, &w_enc, fail("unverifiable"))?);
    let o = secret("checks-feed-other-owner");
    let w_other = soc(&o, &id0, &v1_inner)?;
    out.push(feed_case(
        "other-owner",
        "v1, signed by another key, served at the feed owner's address",
        &f,
        0,
        &w_other,
        fail("verification_failed"),
    )?);
    let id1 = feed_id(&f.topic, 1);
    let w_idx1 = soc(&f.secret, &id1, &v1_inner)?;
    out.push(feed_case(
        "other-index",
        "the owner's update for index 1, served for index 0",
        &f,
        0,
        &w_idx1,
        fail("verification_failed"),
    )?);
    let mut hs = w_v1[..32].to_vec();
    hs.extend_from_slice(&high_s(&w_v1[32..97])?);
    hs.extend_from_slice(&w_v1[97..]);
    out.push(feed_case("high-s", "v1 with its signature in high-s form (s replaced by n − s, v flipped): the same signature mathematically, which Ant refuses", &f, 0, &hs, fail("verification_failed"))?);
    for (name, v) in [
        ("v-29", 29u8),
        ("v-26", 26),
        ("v-31", 31),
        ("v-0", 0),
        ("v-1", 1),
    ] {
        let mut w = w_v1.clone();
        w[96] = v;
        out.push(feed_case(
            name,
            &format!("v1 with the signature's v set to {v}: Ant takes 27 to 30 and subtracts 27"),
            &f,
            0,
            &w,
            fail("verification_failed"),
        )?);
    }
    let mut flipped_v = w_v1.clone();
    flipped_v[96] = if w_v1[96] == 27 { 28 } else { 27 };
    out.push(feed_case(
        "v-other-parity",
        "v1 with v flipped between 27 and 28: another key is recovered",
        &f,
        0,
        &flipped_v,
        fail("verification_failed"),
    )?);
    out.push(feed_case(
        "wrapped-flipped",
        "v1 with a byte of the wrapped chunk's payload flipped after signing",
        &f,
        0,
        &flip(&w_v1, 97 + 8 + 10),
        fail("verification_failed"),
    )?);
    out.push(feed_case(
        "short",
        "104 bytes: an identifier, a signature and 7 bytes, short of the wrapped chunk's span",
        &f,
        0,
        &w_v1[..104],
        fail("verification_failed"),
    )?);
    let mut sig_data = id0.to_vec();
    sig_data.extend_from_slice(&inner_address(&v1_inner)?);
    let raw =
        ant_crypto::sign_prehash(&f.secret, &keccak256(&sig_data)).map_err(|e| e.to_string())?;
    let mut w_raw = id0.to_vec();
    w_raw.extend_from_slice(&raw);
    w_raw.extend_from_slice(&v1_inner);
    out.push(feed_case("no-eip191", "v1 signed over keccak256(id ‖ address) itself, without the EIP-191 prefix: another key is recovered", &f, 0, &w_raw, fail("verification_failed"))?);
    let rsec = ant_crypto::soc::REPLICAS_OWNER_SECRET;
    let rf = Feed {
        secret: rsec,
        owner: owner(&rsec)?,
        topic: f.topic,
    };
    let w_rep = soc(&rf.secret, &id0, &v1_inner)?;
    out.push(feed_case("replicas-owner", "a feed whose owner is the published replicas key: its identifier can't equal the wrapped chunk's address past the first byte, so no update verifies", &rf, 0, &w_rep, fail("verification_failed"))?);
    Ok(out)
}

fn leaves() -> Result<Vec<Value>, Err> {
    let mut out = Vec::new();
    let mut push = |id: &str,
                    note: &str,
                    address: &Addr,
                    l: usize,
                    streamed: &[u8],
                    chunk: Option<&[u8]>,
                    expect: Value|
     -> Result<(), Err> {
        // The case's shape: the fallback is read exactly when the streamed
        // bytes, with the logical length as span, miss the address.
        let matches = streamed.len() == l && cac(span(l as u64), streamed)?.0 == *address;
        let fallback = expect["fallback"]
            .as_bool()
            .or(expect["ok"]["fallback"].as_bool());
        if fallback != Some(!matches) || (chunk.is_some() == matches) {
            return Err(format!("leaf case {id}: its fallback doesn't fit its bytes").into());
        }
        out.push(json!({
            "id": id,
            "note": note,
            "address": h(address),
            "logical_length": l,
            "streamed": bytes(streamed),
            "chunk": chunk.map(bytes),
            "expect": expect,
        }));
        Ok(())
    };
    let short = content::bytes("checks-leaf-short", 100);
    let (short_a, short_w) = cac(span(100), &short)?;
    push(
        "matches",
        "the streamed bytes hash to the address with the logical length: no fallback",
        &short_a,
        100,
        &short,
        None,
        ok(json!({ "fallback": false })),
    )?;
    let full = content::bytes("checks-leaf-full", 4096);
    let (full_a, _) = cac(span(4096), &full)?;
    push(
        "matches-full",
        "a full leaf that matches",
        &full_a,
        4096,
        &full,
        None,
        ok(json!({ "fallback": false })),
    )?;
    let tail = content::bytes("surplus-tail", 100);
    for (id, s, note) in [
        (
            "surplus-payload",
            100u64,
            "span and payload 100 bytes, logical length 60 (1a's shape): the chunk's first 60 payload bytes are the streamed ones",
        ),
        (
            "span-below-logical",
            50,
            "span 50, payload 100, logical length 60",
        ),
        (
            "span-full-block",
            4096,
            "span 4096, payload 100, logical length 60",
        ),
    ] {
        let (a, w) = cac(span(s), &tail)?;
        push(
            id,
            note,
            &a,
            60,
            &tail[..60],
            Some(&w),
            ok(json!({ "fallback": true })),
        )?;
    }
    let last = content::bytes("checks-lone-leaf", 1);
    let (last_a, _) = cac(span(1), &last)?;
    let (wrap_a, wrap_w) = cac(span(1), &last_a)?;
    push(
        "ant-wrapper",
        "Ant's one-reference wrapper (freedom-hq/ant#234): span 1 over the last leaf's address, logical length 1; Ant streams the first byte of its payload, which the chunk authenticates",
        &wrap_a,
        1,
        &last_a[..1],
        Some(&wrap_w),
        ok(json!({ "fallback": true })),
    )?;
    let forty = content::bytes("checks-leaf-forty", 40);
    let (forty_a, forty_w) = cac(span(40), &forty)?;
    let mut streamed = forty.clone();
    streamed.resize(60, 0);
    push(
        "payload-shorter",
        "a leaf of 40 bytes whose parent gives it 60: the chunk holds fewer bytes than the logical length",
        &forty_a,
        60,
        &streamed,
        Some(&forty_w),
        json!({ "fail": "unverifiable", "fallback": true }),
    )?;
    push(
        "streamed-differs",
        "leaf-100's streamed bytes with byte 10 flipped; the chunk is honest",
        &short_a,
        100,
        &flip(&short, 10),
        Some(&short_w),
        json!({ "fail": "verification_failed", "fallback": true }),
    )?;
    push(
        "both-differ",
        "the streamed bytes and the chunk both flipped",
        &short_a,
        100,
        &flip(&short, 10),
        Some(&flip(&short_w, 18)),
        json!({ "fail": "verification_failed", "fallback": true }),
    )?;
    let s = secret("checks-leaf-soc-owner");
    let id = keccak256(b"checks-leaf-soc-id");
    let soc_a = soc_address(&id, &owner(&s)?);
    let soc_w = soc(&s, &id, &short_w)?;
    push(
        "chunk-is-soc",
        "a parent that names a single-owner chunk's address: the stream's bytes can't match, and /chunks answers a valid SOC",
        &soc_a,
        100,
        &short,
        Some(&soc_w),
        json!({ "fail": "unverifiable", "fallback": true }),
    )?;
    Ok(out)
}

pub async fn build() -> Result<Value, Err> {
    Ok(json!({
        "chunks": chunks()?,
        "feed_updates": feed_updates()?,
        "leaves": leaves()?,
        "intermediates": intermediates().await?,
        "manifest_nodes": nodes().await?,
    }))
}

// ---------------------------------------------------------------------------
// Intermediate chunks (0009, Files): references, padding, geometry and
// erasure coding, read from a chunk that passed its address check.

const CHUNK: u64 = 4096;

/// The design's geometry: for `n` data references under a span of `total`,
/// `branch` is the smallest 4096·b^k with total − (n − 1)·branch ≤ branch;
/// the first n − 1 children cover `branch` bytes each, the last the rest.
fn child_lengths(n: usize, total: u64, branching: u64) -> Vec<u64> {
    let before = n.saturating_sub(1) as u64;
    let mut branch = CHUNK;
    while total.saturating_sub(branch.saturating_mul(before)) > branch {
        branch = branch.saturating_mul(branching);
    }
    let mut rest = total;
    (0..n)
        .map(|i| {
            let l = if i + 1 == n { rest } else { branch.min(rest) };
            rest -= l;
            l
        })
        .collect()
}

/// A span's level and plain value (a top byte past 128 carries the level).
fn level_of(span: [u8; 8]) -> (u8, u64) {
    let mut plain = span;
    if plain[7] > 128 {
        let level = plain[7] & 0x7f;
        plain[7] = 0;
        return (level, u64::from_le_bytes(plain));
    }
    (0, u64::from_le_bytes(plain))
}

/// The branching at a level: 128 references, less a full chunk's parities
/// (Bee's `GetMaxShards`, as Ant carries its table).
fn branching(level: u8) -> u64 {
    ant_retrieval::rs::max_shards(level) as u64
}

/// The parities a node of this span holds at this level: Bee's
/// `ReferenceCount`, as Ant carries it; none at level 0 or for a leaf.
fn parities_for(level: u8, total: u64) -> usize {
    if level == 0 || total <= CHUNK {
        return 0;
    }
    ant_retrieval::rs::reference_count(total, level).1
}

/// What the parse yields: the level, the counts, and each data child.
fn inter_ok(level: u8, parities: usize, children: &[(Addr, u64)]) -> Value {
    ok(json!({
        "level": level,
        "data_references": children.len(),
        "parities": parities,
        "children": children
            .iter()
            .map(|(a, l)| json!({ "address": h(a), "length": l }))
            .collect::<Vec<_>>(),
    }))
}

struct Inters {
    out: Vec<Value>,
    net: HashMap<Addr, Vec<u8>>,
}

impl Inters {
    /// A leaf of `len` bytes for a constructed node, held in the network.
    fn leaf(&mut self, label: &str, len: u64) -> Result<(Addr, Vec<u8>), Err> {
        let data = content::bytes(label, len as usize);
        let (a, w) = cac(span(len), &data)?;
        self.net.insert(a, w);
        Ok((a, data))
    }

    /// Records a case after Ant's joiner reads it: `content` is the file
    /// the node's children make, which the join must give back, or `None`
    /// where the design refuses the node and Ant's joiner must too.
    async fn push(
        &mut self,
        id: &str,
        note: &str,
        wire: &[u8],
        expect: Value,
        content: Option<&[u8]>,
    ) -> Result<(), Err> {
        let s: [u8; 8] = wire.get(..8).ok_or("no span")?.try_into()?;
        let (_, total) = level_of(s);
        let address = ant_crypto::bmt_hash_with_span(&s, &wire[8..]).ok_or("payload past 4096")?;
        let fetcher = MemFetcher::new(self.net.clone());
        let joined = ant_retrieval::join(&fetcher, wire, usize::MAX).await;
        let ant = match &joined {
            Ok(b) => json!({ "join": "ok", "length": b.len() }),
            Err(e) => json!({ "join": e.to_string() }),
        };
        let agrees = match (&joined, content) {
            (Ok(b), Some(c)) => b.as_slice() == c,
            (Err(_), None) => true,
            _ => false,
        };
        if !agrees || content.is_some() != expect.get("ok").is_some() {
            return Err(format!("intermediate case {id}: Ant's joiner says {ant}").into());
        }
        self.out.push(json!({
            "id": id,
            "note": note,
            "address": h(&address),
            "wire": bytes(wire),
            "logical_length": total,
            "expect": expect,
            "ant": ant,
        }));
        Ok(())
    }

    /// A node over leaves of the given lengths at `level`, with its
    /// parities (arbitrary addresses: nothing reads them when no data is
    /// missing) and `padding` trailing zero references. Its geometry and
    /// parity count must be the design's.
    async fn built(
        &mut self,
        id: &str,
        note: &str,
        level: u8,
        lengths: &[u64],
        padding: usize,
    ) -> Result<(), Err> {
        let total: u64 = lengths.iter().sum();
        if child_lengths(lengths.len(), total, branching(level)) != lengths {
            return Err(format!("intermediate case {id}: not the design's geometry").into());
        }
        let parities = parities_for(level, total);
        let mut children = Vec::new();
        let mut file = Vec::new();
        for (i, &l) in lengths.iter().enumerate() {
            let (a, d) = self.leaf(&format!("checks-inter-{id}-{i}"), l)?;
            children.push((a, l));
            file.extend_from_slice(&d);
        }
        let mut payload: Vec<u8> = children.iter().flat_map(|(a, _)| *a).collect();
        for p in 0..parities {
            payload.extend_from_slice(&keccak256(
                format!("checks-inter-{id}-parity-{p}").as_bytes(),
            ));
        }
        payload.extend(std::iter::repeat_n(0u8, 32 * padding));
        let mut s = span(total);
        if level > 0 {
            s[7] = 0x80 | level;
        }
        let (_, wire) = cac(s, &payload)?;
        self.push(
            id,
            note,
            &wire,
            inter_ok(level, parities, &children),
            Some(&file),
        )
        .await
    }

    /// The root of Ant's own split of `size` bytes at `level`; its children
    /// and parities read off its payload by the design's rules, and each
    /// child's own span checked against the length its parent gives it.
    async fn split(&mut self, id: &str, note: &str, size: usize, level: u8) -> Result<(), Err> {
        let data = content::bytes(&format!("checks-inter-{id}"), size);
        let split = ant_retrieval::split_bytes_with_redundancy(&data, level);
        for c in &split.chunks {
            self.net.insert(c.address, c.wire.clone());
        }
        let wire = split.root_wire.clone();
        let s: [u8; 8] = wire[..8].try_into()?;
        let (lvl, total) = level_of(s);
        let parities = parities_for(lvl, total);
        let refs: Vec<Addr> = wire[8..]
            .chunks(32)
            .map(<[u8; 32]>::try_from)
            .collect::<Result<_, _>>()?;
        let n = refs
            .len()
            .checked_sub(parities)
            .ok_or("fewer references than parities")?;
        let lengths = child_lengths(n, total, branching(lvl));
        let mut children = Vec::new();
        // What Ant's joiner gives: a leaf child's payload up to its length
        // (Ant's one-reference wrapper streams its own payload's first
        // byte, ant-lone-reference), else the content beneath it.
        let mut joined = Vec::new();
        let mut offset = 0usize;
        for (a, l) in refs[..n].iter().zip(lengths) {
            let child = self.net.get(a).ok_or("a child the split didn't write")?;
            let own: [u8; 8] = child[..8].try_into()?;
            if level_of(own).1 != l {
                return Err(
                    format!("intermediate case {id}: a child's span isn't its length").into(),
                );
            }
            let len = usize::try_from(l)?;
            if l <= CHUNK {
                joined.extend_from_slice(child.get(8..8 + len).ok_or("a short leaf")?);
            } else {
                joined.extend_from_slice(&data[offset..offset + len]);
            }
            offset += len;
            children.push((*a, l));
        }
        self.push(
            id,
            note,
            &wire,
            inter_ok(lvl, parities, &children),
            Some(&joined),
        )
        .await
    }
}

async fn intermediates() -> Result<Vec<Value>, Err> {
    let mut c = Inters {
        out: Vec::new(),
        net: HashMap::new(),
    };
    c.built(
        "two-references",
        "two full leaves: the fewest references Bee writes",
        0,
        &[4096, 4096],
        0,
    )
    .await?;
    c.built(
        "last-short",
        "three references, the last child 1,808 bytes",
        0,
        &[4096, 4096, 1808],
        0,
    )
    .await?;
    c.built(
        "references-128",
        "128 full leaves: a full payload",
        0,
        &[4096; 128],
        0,
    )
    .await?;
    c.built("zero-padding", "last-short with two all-zero references after it: trailing zero references are padding, not children", 0, &[4096, 4096, 1808], 2).await?;
    // A zero reference between two others is a child; the network holds a
    // chunk at the zero address for Ant's joiner (whose fetcher doesn't
    // check addresses), where the walk's own check would refuse it.
    let (a, da) = c.leaf("checks-inter-zero-inside-0", 4096)?;
    let zero_leaf = content::bytes("checks-inter-zero-inside-1", 4096);
    let (_, zw) = cac(span(4096), &zero_leaf)?;
    c.net.insert([0u8; 32], zw);
    let (b, db) = c.leaf("checks-inter-zero-inside-2", 100)?;
    let mut payload = a.to_vec();
    payload.extend_from_slice(&[0u8; 32]);
    payload.extend_from_slice(&b);
    let (_, w) = cac(span(8292), &payload)?;
    let file = [da, zero_leaf, db].concat();
    c.push("zero-reference-inside", "a zero reference between two others: only trailing zeros are padding, so it is the second child (whose chunk then fails its own address check)", &w,
        inter_ok(0, 0, &[(a, 4096), ([0u8; 32], 4096), (b, 100)]), Some(&file)).await?;
    // One reference over a two-leaf node: Ant reads a node of one.
    let (a0, d0) = c.leaf("checks-inter-one-0", 4096)?;
    let (a1, d1) = c.leaf("checks-inter-one-1", 4096)?;
    let (inner, inner_w) = cac(span(8192), &[a0, a1].concat())?;
    c.net.insert(inner, inner_w);
    let (_, w) = cac(span(8192), &inner)?;
    c.push("one-reference", "one reference with a span of 8,192: its only child is the whole span, an intermediate of two leaves; Ant reads it, and so does the core", &w,
        inter_ok(0, 0, &[(inner, 8192)]), Some(&[d0, d1].concat())).await?;
    c.split("two-levels-ant", "Ant's split of 524,289 bytes: 128 leaves' node, then its one-reference wrapper of the last leaf (ant-lone-reference)", 524_289, 0).await?;
    c.split(
        "two-levels",
        "Ant's split of 2 MiB: four children of 128 leaves each",
        2 * 1024 * 1024,
        0,
    )
    .await?;
    for level in 1..=4u8 {
        let full = ant_retrieval::rs::max_shards(level);
        c.split(&format!("level-{level}-full"), &format!("Ant's split at level {level} of {full} leaves: the most data references a node holds at that level, then its parities"), full * 4096, level).await?;
        c.split(
            &format!("level-{level}-ten"),
            &format!("Ant's split at level {level} of ten leaves: Bee's parity count for ten"),
            10 * 4096,
            level,
        )
        .await?;
        c.split(&format!("level-{level}-two-levels"), &format!("Ant's split at level {level} of {} leaves: a full node and the leftover leaf, carried up; the first child's length is {full} leaves", full + 1), (full + 1) * 4096, level).await?;
        c.built(
            &format!("level-{level}-last-short"),
            &format!("level {level}, three leaves, the last 1,000 bytes"),
            level,
            &[4096, 4096, 1000],
            0,
        )
        .await?;
    }
    for (id, top) in [("level-5", 0x85u8), ("level-127", 0xff)] {
        let lengths = [4096u64, 4096];
        let mut children = Vec::new();
        let mut file = Vec::new();
        for (i, &l) in lengths.iter().enumerate() {
            let (a, d) = c.leaf(&format!("checks-inter-{id}-{i}"), l)?;
            children.push((a, l));
            file.extend_from_slice(&d);
        }
        let mut s = span(8192);
        s[7] = top;
        let payload: Vec<u8> = children.iter().flat_map(|(a, _)| *a).collect();
        let (_, w) = cac(s, &payload)?;
        c.push(id, &format!("two full leaves, the span's top byte {top:#04x}: level {}, which no table has, so no parities and a branching of 128, as Ant reads it", top & 0x7f), &w,
            inter_ok(top & 0x7f, 0, &children), Some(&file)).await?;
    }
    let (a, _) = c.leaf("checks-inter-bad-0", 4096)?;
    let mut payload = a.to_vec();
    payload.extend_from_slice(&a[..1]);
    let (_, w) = cac(span(8192), &payload)?;
    c.push(
        "not-whole-references",
        "a payload of 33 bytes: not whole references",
        &w,
        fail("unverifiable"),
        None,
    )
    .await?;
    let (_, w) = cac(span(8192), &[0u8; 64])?;
    c.push(
        "all-zero",
        "two all-zero references: no reference once the padding goes",
        &w,
        fail("unverifiable"),
        None,
    )
    .await?;
    let (_, w) = cac(span(8192), &[])?;
    c.push(
        "no-references",
        "span 8,192 and no payload: a valid chunk, but no reference to read",
        &w,
        fail("unverifiable"),
        None,
    )
    .await?;
    // Level 1 at ten leaves' span implies four parities: four references
    // leave no data reference.
    let mut s = span(10 * 4096);
    s[7] = 0x81;
    let refs: Vec<u8> = (0..4)
        .flat_map(|i| keccak256(format!("checks-inter-few-{i}").as_bytes()))
        .collect();
    let (_, w) = cac(s, &refs)?;
    c.push("parities-not-fewer-than-references", "level 1 with a span of ten leaves, whose four parities leave four references no data reference", &w, fail("unverifiable"), None).await?;
    Ok(c.out)
}

// ---------------------------------------------------------------------------
// Mantaray nodes (0009, Manifests and feeds; Bounded decoding): a node's
// joined bytes, decoded as Ant decodes them, within the core's caps.

/// A node's bytes as `(prefix, unit, count)` segments: `prefix` once,
/// then `unit` repeated `count` times.
type Seg = (Vec<u8>, Vec<u8>, usize);
type Segs = Vec<Seg>;

/// The metadata keys the walk reads, the only ones a decoded fork keeps.
pub const KEPT_METADATA: [&str; 7] = [
    "Content-Type",
    "Filename",
    "website-index-document",
    "website-error-document",
    "swarm-feed-owner",
    "swarm-feed-topic",
    "swarm-feed-type",
];

const MAX_NODE: usize = 1 << 20;

fn version(v: &str) -> [u8; 31] {
    let h = keccak256(v.as_bytes());
    let mut out = [0u8; 31];
    out.copy_from_slice(&h[..31]);
    out
}

/// A fork as the bytes lay it out, every field the case's to set.
struct RawFork {
    /// The bitmap bit it sits under.
    bit: u8,
    node_type: u8,
    prefix_len: u8,
    /// Up to 30 bytes, zero-padded.
    prefix: Vec<u8>,
    child: Vec<u8>,
    /// The metadata as `(prefix, unit, count)` segments, and the length
    /// its 2-byte field declares (its own length unless a case lies).
    meta: Option<(Segs, Option<u16>)>,
}

fn meta_len(segs: &[Seg]) -> usize {
    segs.iter().map(|(p, u, n)| p.len() + u.len() * n).sum()
}

/// A node's bytes as segments for `parts`, so long metadata stays short in
/// the file. Obfuscation needs whole bytes, so only a node held whole
/// (`key` non-zero) is obfuscated.
fn raw_node(
    key: [u8; 32],
    ver: [u8; 31],
    ref_size: u8,
    entry: &[u8],
    forks: &[RawFork],
    tail: &[u8],
) -> Segs {
    let mut segs: Segs = Vec::new();
    let mut cur = key.to_vec();
    cur.extend_from_slice(&ver);
    cur.push(ref_size);
    cur.extend_from_slice(entry);
    let mut bitmap = [0u8; 32];
    for f in forks {
        bitmap[usize::from(f.bit / 8)] |= 1 << (f.bit % 8);
    }
    cur.extend_from_slice(&bitmap);
    for f in forks {
        cur.push(f.node_type);
        cur.push(f.prefix_len);
        let mut p = f.prefix.clone();
        p.resize(30, 0);
        cur.extend_from_slice(&p);
        cur.extend_from_slice(&f.child);
        if let Some((m, declared)) = &f.meta {
            let len = declared.unwrap_or(meta_len(m) as u16);
            cur.extend_from_slice(&len.to_be_bytes());
            for (p, u, n) in m {
                cur.extend_from_slice(p);
                if *n > 0 {
                    segs.push((std::mem::take(&mut cur), u.clone(), *n));
                }
            }
        }
    }
    cur.extend_from_slice(tail);
    segs.push((cur, Vec::new(), 0));
    if key != [0u8; 32] {
        let mut whole: Vec<u8> = segs
            .iter()
            .flat_map(|(p, u, n)| {
                let mut v = p.clone();
                for _ in 0..*n {
                    v.extend_from_slice(u);
                }
                v
            })
            .collect();
        for chunk in whole[32..].chunks_mut(32) {
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= key[i];
            }
        }
        return vec![(whole, Vec::new(), 0)];
    }
    segs
}

fn seg(text: &str) -> Segs {
    vec![(text.as_bytes().to_vec(), Vec::new(), 0)]
}

/// Bee's newline padding of a fork's metadata (`manifest_writer.rs`).
fn bee_padded(meta: &str) -> String {
    let with_size = meta.len() + 2;
    let pad = match with_size.cmp(&32) {
        std::cmp::Ordering::Less => 32 - with_size,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 32 - with_size % 32,
    };
    format!("{meta}{}", "\n".repeat(pad))
}

struct NodeCases {
    out: Vec<Value>,
    net: HashMap<Addr, Vec<u8>>,
    /// The value node each file reference's fork names.
    children: Vec<(Addr, Addr)>,
}

/// What a lookup of a fork's prefix through Ant should give: the child's
/// entry, and the kept metadata.
struct Probe {
    path: String,
    entry: Addr,
    kept: Vec<(String, String)>,
}

impl NodeCases {
    /// The `i`th value node: an entry of a file reference, no forks.
    fn child(&mut self, i: usize) -> Result<(Addr, Addr), Err> {
        while self.children.len() <= i {
            let file = keccak256(format!("checks-node-file-{}", self.children.len()).as_bytes());
            let node = crate::mantaray::Node {
                obfuscation_key: [0; 32],
                ref_size: 32,
                entry: file.to_vec(),
                forks: Vec::new(),
            }
            .marshal();
            let (a, w) = ant_crypto::cac_new(&node).ok_or("value node past a chunk")?;
            self.net.insert(a, w);
            self.children.push((a, file));
        }
        Ok(self.children[i])
    }

    /// Records a case after Ant reads the node: stored as a file, then
    /// looked up through `lookup_path`, once at a path no fork holds (so
    /// the node is parsed whole, or refused) and once per probe.
    async fn push(
        &mut self,
        id: &str,
        note: &str,
        segs: &[Seg],
        expect: Value,
        probes: &[Probe],
        deviation: Option<&str>,
    ) -> Result<(), Err> {
        let seg_refs: Vec<(&[u8], &[u8], usize)> = segs
            .iter()
            .map(|(p, u, n)| (p.as_slice(), u.as_slice(), *n))
            .collect();
        let (node, node_v) = super::parts(&seg_refs);
        // Stored as Bee splits it: Ant's own split of a node whose last
        // leaf is a level's lone one would read back wrong
        // (ant-lone-reference).
        let (root, chunks) = crate::bee::split(&node).ok_or("Bee's split")?;
        let mut net = self.net.clone();
        for (a, w) in chunks {
            net.insert(a, w);
        }
        let fetcher = MemFetcher::new(net);
        let absent = format!("{}absent", char::from(1u8));
        let probe = ant_retrieval::lookup_path(&fetcher, &root, &absent).await;
        let detail = probe
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default();
        let parsed = match probe {
            Err(
                ant_retrieval::ManifestError::TooShort(_)
                | ant_retrieval::ManifestError::InvalidRefLength(_)
                | ant_retrieval::ManifestError::InvalidMetadata(_)
                | ant_retrieval::ManifestError::UnsupportedVersion(_),
            ) => "malformed",
            Err(ant_retrieval::ManifestError::NotAManifest) => "not_a_manifest",
            _ => "parsed",
        };
        let mut looked = Vec::new();
        for p in probes {
            let r = ant_retrieval::lookup_path(&fetcher, &root, &p.path)
                .await
                .map_err(|e| format!("node case {id}: Ant's lookup of {:?}: {e}", p.path))?;
            let mut kept: Vec<(String, String)> = r
                .metadata
                .iter()
                .filter(|(k, _)| KEPT_METADATA.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            kept.sort();
            let mut want = p.kept.clone();
            want.sort();
            if r.data_ref != p.entry || kept != want {
                return Err(format!("node case {id}: Ant's lookup of {:?} differs", p.path).into());
            }
            looked.push(json!(p.path));
        }
        let want = match (expect.get("ok"), expect["fail"].as_str()) {
            (Some(v), _) if v["manifest"] == false => "not_a_manifest",
            (Some(_), _) => "parsed",
            (None, Some("malformed")) => "malformed",
            // Past the core's cap, Ant still reads it (manifest-node-cap).
            (None, Some("unverifiable")) => "parsed",
            _ => "?",
        };
        if parsed != want
            || (want == "parsed" && expect.get("fail").is_some() != deviation.is_some())
        {
            return Err(format!("node case {id}: Ant says {parsed} ({detail})").into());
        }
        let mut case = json!({
            "id": id,
            "note": note,
            "node": node_v,
            "expect": expect,
            "ant": { "decoded": parsed, "lookups": looked },
        });
        if let Some(d) = deviation {
            case["deviation"] = json!(d);
        }
        self.out.push(case);
        Ok(())
    }
}

fn fork_json(bit: u8, node_type: u8, prefix: &[u8], child: &[u8], kept: &[(&str, &str)]) -> Value {
    let mut m = serde_json::Map::new();
    for (k, v) in kept {
        m.insert((*k).to_string(), json!(v));
    }
    json!({ "byte": bit, "type": node_type, "prefix": h(prefix), "child": h(child), "metadata": m })
}

fn node_ok(ref_size: u8, entry: &[u8], forks: Vec<Value>) -> Value {
    ok(json!({ "manifest": true, "ref_size": ref_size, "entry": h(entry), "forks": forks }))
}

const VALUE: u8 = crate::mantaray::TYPE_VALUE;
const META: u8 = crate::mantaray::TYPE_WITH_METADATA;

/// A flat object of exactly `len` bytes: Content-Type, then unknown keys
/// (repeated, as JSON allows, the last winning) to fill it.
fn max_metadata(len: usize) -> Segs {
    let head = r#"{"Content-Type":"text/plain""#;
    let unit = format!(r#","x":"{}""#, "v".repeat(57));
    let room = len - head.len();
    let count = (room - 8) / unit.len();
    let fill = room - count * unit.len() - 8;
    let last = format!(r#","y":"{}"}}"#, "w".repeat(fill));
    vec![
        (head.as_bytes().to_vec(), unit.into_bytes(), count),
        (last.into_bytes(), Vec::new(), 0),
    ]
}

async fn nodes() -> Result<Vec<Value>, Err> {
    let mut c = NodeCases {
        out: Vec::new(),
        net: HashMap::new(),
        children: Vec::new(),
    };
    let v02 = version("mantaray:0.2");
    let v01 = version("mantaray:0.1");
    let (ca, fa) = c.child(0)?;
    let (cb, fb) = c.child(1)?;
    let plain_meta =
        crate::mantaray::metadata(&[("Content-Type", "text/plain"), ("Filename", "a.txt")]);
    let plain_forks = |key: [u8; 32]| {
        raw_node(
            key,
            v02,
            32,
            &[0u8; 32],
            &[
                RawFork {
                    bit: b'a',
                    node_type: VALUE | META,
                    prefix_len: 5,
                    prefix: b"a.txt".to_vec(),
                    child: ca.to_vec(),
                    meta: Some((seg(&bee_padded(&plain_meta)), None)),
                },
                RawFork {
                    bit: b'b',
                    node_type: VALUE,
                    prefix_len: 6,
                    prefix: b"b.html".to_vec(),
                    child: cb.to_vec(),
                    meta: None,
                },
            ],
            &[],
        )
    };
    // Hold the case writer to the generator's (itself held to Ant's).
    let honest = crate::mantaray::Node {
        obfuscation_key: [0; 32],
        ref_size: 32,
        entry: vec![0; 32],
        forks: vec![
            crate::mantaray::Fork {
                node_type: VALUE | META,
                prefix: b"a.txt".to_vec(),
                child: ca.to_vec(),
                metadata: Some(plain_meta.clone()),
            },
            crate::mantaray::Fork {
                node_type: VALUE,
                prefix: b"b.html".to_vec(),
                child: cb.to_vec(),
                metadata: None,
            },
        ],
    }
    .marshal();
    if plain_forks([0; 32]).concat_bytes() != honest {
        return Err("the node cases' writer differs from the generator's mantaray writer".into());
    }
    let plain_expect = node_ok(
        32,
        &[0u8; 32],
        vec![
            fork_json(
                b'a',
                VALUE | META,
                b"a.txt",
                &ca,
                &[("Content-Type", "text/plain"), ("Filename", "a.txt")],
            ),
            fork_json(b'b', VALUE, b"b.html", &cb, &[]),
        ],
    );
    let plain_probes = || {
        vec![
            Probe {
                path: "a.txt".into(),
                entry: fa,
                kept: vec![
                    ("Content-Type".into(), "text/plain".into()),
                    ("Filename".into(), "a.txt".into()),
                ],
            },
            Probe {
                path: "b.html".into(),
                entry: fb,
                kept: vec![],
            },
        ]
    };
    c.push(
        "plain",
        "two forks, one with Bee's padded metadata",
        &plain_forks([0; 32]),
        plain_expect.clone(),
        &plain_probes(),
        None,
    )
    .await?;
    c.push(
        "obfuscated",
        "the same node under a non-zero obfuscation key",
        &plain_forks(keccak256(b"checks-node-key")),
        plain_expect,
        &plain_probes(),
        None,
    )
    .await?;
    c.push(
        "version-0.1",
        "mantaray:0.1, whose forks carry no metadata even with the metadata bit set",
        &raw_node(
            [0; 32],
            v01,
            32,
            &[0u8; 32],
            &[RawFork {
                bit: b'a',
                node_type: VALUE | META,
                prefix_len: 5,
                prefix: b"a.txt".to_vec(),
                child: ca.to_vec(),
                meta: None,
            }],
            &[],
        ),
        node_ok(
            32,
            &[0u8; 32],
            vec![fork_json(b'a', VALUE | META, b"a.txt", &ca, &[])],
        ),
        &[Probe {
            path: "a.txt".into(),
            entry: fa,
            kept: vec![],
        }],
        None,
    )
    .await?;
    c.push(
        "not-a-manifest",
        "200 bytes without a version hash: a file, which Ant serves as the reference's bytes",
        &[(content::bytes("checks-node-raw", 200), Vec::new(), 0)],
        ok(json!({ "manifest": false })),
        &[],
        None,
    )
    .await?;
    let mut short = plain_forks([0; 32]).concat_bytes();
    short.truncate(64 + 10);
    c.push(
        "entry-truncated",
        "a version hash, then 10 of the entry's 32 bytes",
        &[(short, Vec::new(), 0)],
        fail("malformed"),
        &[],
        None,
    )
    .await?;
    let mut short = plain_forks([0; 32]).concat_bytes();
    short.truncate(64 + 32 + 20);
    c.push(
        "bitmap-truncated",
        "the entry, then 20 of the fork bitmap's 32 bytes",
        &[(short, Vec::new(), 0)],
        fail("malformed"),
        &[],
        None,
    )
    .await?;
    c.push(
        "ref-size-0",
        "an empty node: reference size 0, no entry, no forks, which Ant accepts",
        &raw_node([0; 32], v02, 0, &[], &[], &[]),
        node_ok(0, &[], vec![]),
        &[],
        None,
    )
    .await?;
    let wide: Vec<u8> = [ca, keccak256(b"checks-node-enc-key")].concat();
    c.push("ref-size-64", "64-byte references (an encrypted manifest's): decoded, and refused by the walk as encrypted", &raw_node([0; 32], v02, 64, &[0u8; 64], &[
        RawFork { bit: b'a', node_type: VALUE, prefix_len: 5, prefix: b"a.txt".to_vec(), child: wide.clone(), meta: None },
    ], &[]), node_ok(64, &[0u8; 64], vec![fork_json(b'a', VALUE, b"a.txt", &wide, &[])]), &[], None).await?;
    c.push(
        "ref-size-33",
        "reference size 33",
        &raw_node([0; 32], v02, 33, &[0u8; 33], &[], &[]),
        fail("malformed"),
        &[],
        None,
    )
    .await?;
    for (id, len, expect) in [
        ("prefix-length-0", 0u8, false),
        ("prefix-length-31", 31, false),
        ("prefix-length-30", 30, true),
    ] {
        let prefix = vec![b'a'; usize::from(len.min(30))];
        let segs = raw_node(
            [0; 32],
            v02,
            32,
            &[0u8; 32],
            &[RawFork {
                bit: b'a',
                node_type: VALUE,
                prefix_len: len,
                prefix: prefix.clone(),
                child: ca.to_vec(),
                meta: None,
            }],
            &[],
        );
        let (e, probes) = if expect {
            (
                node_ok(
                    32,
                    &[0u8; 32],
                    vec![fork_json(b'a', VALUE, &prefix, &ca, &[])],
                ),
                vec![Probe {
                    path: "a".repeat(30),
                    entry: fa,
                    kept: vec![],
                }],
            )
        } else {
            (fail("malformed"), vec![])
        };
        c.push(
            id,
            &format!("a fork whose prefix length is {len}: 1 to 30 are read"),
            &segs,
            e,
            &probes,
            None,
        )
        .await?;
    }
    let mut forks = Vec::new();
    let mut expect = Vec::new();
    let mut probes = Vec::new();
    for b in 0..=255u8 {
        let (cc, fc) = c.child(2 + usize::from(b))?;
        forks.push(RawFork {
            bit: b,
            node_type: VALUE,
            prefix_len: 1,
            prefix: vec![b],
            child: cc.to_vec(),
            meta: None,
        });
        expect.push(fork_json(b, VALUE, &[b], &cc, &[]));
        if b.is_ascii_alphanumeric() && b % 8 == 1 {
            probes.push(Probe {
                path: char::from(b).to_string(),
                entry: fc,
                kept: vec![],
            });
        }
    }
    c.push(
        "forks-256",
        "a fork for every first byte: 256, the most a bitmap holds",
        &raw_node([0; 32], v02, 32, &[0u8; 32], &forks, &[]),
        node_ok(32, &[0u8; 32], expect),
        &probes,
        None,
    )
    .await?;
    let mut two = raw_node(
        [0; 32],
        v02,
        32,
        &[0u8; 32],
        &[RawFork {
            bit: b'a',
            node_type: VALUE,
            prefix_len: 5,
            prefix: b"a.txt".to_vec(),
            child: ca.to_vec(),
            meta: None,
        }],
        &[],
    )
    .concat_bytes();
    two[64 + 32 + usize::from(b'b' / 8)] |= 1 << (b'b' % 8);
    c.push(
        "fork-missing",
        "a bitmap of two forks over the bytes of one",
        &[(two, Vec::new(), 0)],
        fail("malformed"),
        &[],
        None,
    )
    .await?;
    c.push("fork-under-other-byte", "the bitmap's bit for 'a' over a fork whose prefix starts with 'b': it sits under 'a', so no path reaches it", &raw_node([0; 32], v02, 32, &[0u8; 32], &[
        RawFork { bit: b'a', node_type: VALUE, prefix_len: 5, prefix: b"b.txt".to_vec(), child: ca.to_vec(), meta: None },
    ], &[]), node_ok(32, &[0u8; 32], vec![fork_json(b'a', VALUE, b"b.txt", &ca, &[])]), &[], None).await?;

    // Metadata: one fork, its metadata as given.
    let one = |m: Segs, declared: Option<u16>| {
        raw_node(
            [0; 32],
            v02,
            32,
            &[0u8; 32],
            &[RawFork {
                bit: b'a',
                node_type: VALUE | META,
                prefix_len: 5,
                prefix: b"a.txt".to_vec(),
                child: ca.to_vec(),
                meta: Some((m, declared)),
            }],
            &[],
        )
    };
    let a_ok = |kept: &[(&str, &str)]| {
        node_ok(
            32,
            &[0u8; 32],
            vec![fork_json(b'a', VALUE | META, b"a.txt", &ca, kept)],
        )
    };
    let a_probe = |kept: &[(&str, &str)]| {
        vec![Probe {
            path: "a.txt".into(),
            entry: fa,
            kept: kept
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }]
    };
    let ct = [("Content-Type", "text/plain")];
    c.push("metadata-max-length", "metadata of 65,535 bytes, its 2-byte length's most: Content-Type, then unknown keys, repeated, which only cost time", &one(max_metadata(65_535), None), a_ok(&ct), &a_probe(&ct), None).await?;
    let head = r#"{"Content-Type":"text/plain","x":"#;
    let k = (65_535 - head.len() - 4) / 6;
    let pad = 65_535 - head.len() - 6 * k - 4;
    let deep = vec![
        (head.as_bytes().to_vec(), br#"{"x":"#.to_vec(), k),
        (br#""v""#.to_vec(), b"}".to_vec(), k),
        (format!("{}}}", " ".repeat(pad)).into_bytes(), Vec::new(), 0),
    ];
    c.push("metadata-nested-deep", &format!("65,535 bytes of metadata whose value for x nests {k} objects deep: only a flat object of strings is read, so it is refused where the first value isn't a string, without descending"), &one(deep, None), fail("malformed"), &[], None).await?;
    for (id, text, note) in [
        (
            "metadata-nested",
            r#"{"Content-Type":{"a":"b"}}"#,
            "a value that is an object",
        ),
        (
            "metadata-number",
            r#"{"Content-Type":"text/plain","size":12}"#,
            "a value that is a number",
        ),
        (
            "metadata-array",
            r#"{"Content-Type":["text/plain"]}"#,
            "a value that is an array",
        ),
        (
            "metadata-not-object",
            r#"["Content-Type","text/plain"]"#,
            "an array, not an object",
        ),
        (
            "metadata-unterminated",
            r#"{"Content-Type":"text/plain"#,
            "a string that never ends",
        ),
    ] {
        c.push(
            id,
            note,
            &one(seg(text), None),
            fail("malformed"),
            &[],
            None,
        )
        .await?;
    }
    c.push(
        "metadata-trailing-text",
        "text after the object, which Ant's reader stops before: the object is read",
        &one(seg(r#"{"Content-Type":"text/plain"}x"#), None),
        a_ok(&ct),
        &a_probe(&ct),
        None,
    )
    .await?;
    let bad_utf8 = vec![
        (br#"{"Content-Type":"text/pl"#.to_vec(), Vec::new(), 0),
        (vec![0xff], Vec::new(), 0),
        (br#"ain"}"#.to_vec(), Vec::new(), 0),
    ];
    c.push(
        "metadata-not-utf8",
        "a 0xff byte inside a string",
        &one(bad_utf8, None),
        fail("malformed"),
        &[],
        None,
    )
    .await?;
    c.push(
        "metadata-length-past-end",
        "a metadata length 100 bytes past the node's end",
        &one(seg(r#"{"Content-Type":"text/plain"}"#), Some(129)),
        fail("malformed"),
        &[],
        None,
    )
    .await?;
    c.push(
        "metadata-empty",
        "the metadata bit with a length of 0",
        &one(Vec::new(), None),
        a_ok(&[]),
        &a_probe(&[]),
        None,
    )
    .await?;
    c.push(
        "metadata-newlines",
        "metadata of Bee's newline padding only",
        &one(seg("\n\n\n\n\n\n"), None),
        a_ok(&[]),
        &a_probe(&[]),
        None,
    )
    .await?;
    c.push(
        "metadata-duplicate-key",
        "Content-Type twice: the last wins, as in Ant's map",
        &one(
            seg(r#"{"Content-Type":"text/plain","Content-Type":"text/html"}"#),
            None,
        ),
        a_ok(&[("Content-Type", "text/html")]),
        &a_probe(&[("Content-Type", "text/html")]),
        None,
    )
    .await?;
    c.push(
        "metadata-unknown-keys",
        "keys the walk doesn't read are dropped",
        &one(
            seg(r#"{"Content-Type":"text/plain","foo":"bar","Filename":"a.txt"}"#),
            None,
        ),
        a_ok(&[("Content-Type", "text/plain"), ("Filename", "a.txt")]),
        &a_probe(&[("Content-Type", "text/plain"), ("Filename", "a.txt")]),
        None,
    )
    .await?;
    // Escapes, built at run time: \/, \", \n, and a \u escape of é.
    let bs = '\\';
    let esc = format!(
        r#"{{"Content-Type":"text{bs}/plain","Filename":"caf{bs}u00e9 {bs}"x{bs}"{bs}n.txt"}}"#
    );
    let fname = "caf\u{e9} \"x\"\n.txt";
    c.push(
        "metadata-escapes",
        "JSON escapes in a value: \\/, \\\", \\n and a \\u escape",
        &one(seg(&esc), None),
        a_ok(&[("Content-Type", "text/plain"), ("Filename", fname)]),
        &a_probe(&[("Content-Type", "text/plain"), ("Filename", fname)]),
        None,
    )
    .await?;

    // Size: maximal metadata on fifteen forks, then the 1 MiB cap.
    let mut forks = Vec::new();
    let mut expect = Vec::new();
    let mut probes = Vec::new();
    for i in 0..15u8 {
        let b = b'a' + i;
        let (cc, fc) = c.child(300 + usize::from(i))?;
        forks.push(RawFork {
            bit: b,
            node_type: VALUE | META,
            prefix_len: 1,
            prefix: vec![b],
            child: cc.to_vec(),
            meta: Some((max_metadata(65_535), None)),
        });
        expect.push(fork_json(b, VALUE | META, &[b], &cc, &ct));
        probes.push(Probe {
            path: char::from(b).to_string(),
            entry: fc,
            kept: ct
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        });
    }
    let segs = raw_node([0; 32], v02, 32, &[0u8; 32], &forks, &[]);
    let size = segs.concat_bytes().len();
    c.push(
        "metadata-max-every-fork",
        &format!(
            "fifteen forks, each with 65,535 bytes of metadata: {size} bytes, within the 1 MiB cap"
        ),
        &segs,
        node_ok(32, &[0u8; 32], expect),
        &probes,
        None,
    )
    .await?;
    for (id, size, note) in [
        (
            "node-1-mib",
            MAX_NODE,
            "a node of exactly 1 MiB: sixteen forks of near-maximal metadata",
        ),
        (
            "node-past-1-mib",
            MAX_NODE + 1,
            "a node of 1 MiB and one byte: past the core's cap, which Ant's 32 MiB allows (manifest-node-cap)",
        ),
    ] {
        let header = 32 + 31 + 1 + 32 + 32;
        let per_fork = 1 + 1 + 30 + 32 + 2;
        let mut forks = Vec::new();
        let mut expect = Vec::new();
        let total = size - header - 16 * per_fork;
        for i in 0..16u8 {
            let b = b'a' + i;
            let (cc, _) = c.child(400 + usize::from(i))?;
            let len = if i < 15 { 65_535 } else { total - 15 * 65_535 };
            forks.push(RawFork {
                bit: b,
                node_type: VALUE | META,
                prefix_len: 1,
                prefix: vec![b],
                child: cc.to_vec(),
                meta: Some((max_metadata(len), None)),
            });
            expect.push(fork_json(b, VALUE | META, &[b], &cc, &ct));
        }
        let segs = raw_node([0; 32], v02, 32, &[0u8; 32], &forks, &[]);
        if segs.concat_bytes().len() != size {
            return Err(format!("node case {id}: {} bytes", segs.concat_bytes().len()).into());
        }
        let (e, dev) = if size > MAX_NODE {
            (fail("unverifiable"), Some("manifest-node-cap"))
        } else {
            (node_ok(32, &[0u8; 32], expect), None)
        };
        c.push(id, note, &segs, e, &[], dev).await?;
    }
    Ok(c.out)
}

trait ConcatBytes {
    fn concat_bytes(&self) -> Vec<u8>;
}

impl ConcatBytes for Segs {
    fn concat_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for (p, u, n) in self {
            v.extend_from_slice(p);
            for _ in 0..*n {
                v.extend_from_slice(u);
            }
        }
        v
    }
}
