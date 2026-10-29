//! Swarm piece checks: content-addressed chunks, feed updates and leaves
//! (0009, Chunks, Manifests and feeds, Leaves).

use super::{Err, bytes, fail, ok};
use crate::content;
use ant_crypto::keccak256;
use k256::elliptic_curve::PrimeField;
use serde_json::{Value, json};

pub(super) type Addr = [u8; 32];

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

pub(super) fn cac(span: [u8; 8], payload: &[u8]) -> Result<(Addr, Vec<u8>), Err> {
    let addr = ant_crypto::bmt_hash_with_span(&span, payload).ok_or("payload past 4096 bytes")?;
    let mut wire = span.to_vec();
    wire.extend_from_slice(payload);
    Ok((addr, wire))
}

pub(super) fn span(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

pub(super) fn secret(label: &str) -> [u8; 32] {
    keccak256(label.as_bytes())
}

pub(super) fn owner(secret: &[u8; 32]) -> Result<[u8; 20], Err> {
    let sk = k256::ecdsa::SigningKey::from_bytes(secret.into()).map_err(|e| e.to_string())?;
    Ok(ant_crypto::ethereum_address_from_public_key(
        sk.verifying_key(),
    ))
}

pub(super) fn soc_address(id: &Addr, owner: &[u8; 20]) -> Addr {
    let mut input = id.to_vec();
    input.extend_from_slice(owner);
    keccak256(&input)
}

pub(super) fn feed_id(topic: &Addr, index: u64) -> Addr {
    let mut input = topic.to_vec();
    input.extend_from_slice(&index.to_be_bytes());
    keccak256(&input)
}

/// A single-owner chunk: `id ‖ signature ‖ inner wire`, the signature over
/// the EIP-191 digest of `keccak256(id ‖ inner address)`, as Bee signs.
pub(super) fn soc(secret: &[u8; 32], id: &Addr, inner: &[u8]) -> Result<Vec<u8>, Err> {
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

pub fn build() -> Result<Value, Err> {
    Ok(json!({
        "chunks": chunks()?,
        "feed_updates": feed_updates()?,
        "leaves": leaves()?,
    }))
}
