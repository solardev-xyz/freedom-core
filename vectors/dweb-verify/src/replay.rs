//! What a replay with no node does with the IPFS half: rebuild every block
//! from the vectors alone (ipfs.blocks, and each leaf from its content),
//! then every CAR Kubo answered, to its recorded length and SHA-256.

use crate::car;
use crate::content;
use base64::Engine;
use cid::Cid;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type Err = Box<dyn std::error::Error>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, Err> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("{key} missing in {v}").into())
}

fn num(v: &Value, key: &str) -> Result<usize, Err> {
    Ok(usize::try_from(
        v[key]
            .as_u64()
            .ok_or_else(|| format!("{key} missing in {v}"))?,
    )?)
}

/// A leaf's block: its slice of the file's content, framed by its dag-pb
/// prefix and suffix when it has them.
fn leaf(data: &[u8], l: &Value) -> Result<Vec<u8>, Err> {
    let from = num(l, "from")?;
    let length = num(l, "length")?;
    let slice = data
        .get(from..from + length)
        .ok_or("a leaf past its file's content")?;
    let mut out = match l["prefix"].as_str() {
        Some(p) => B64.decode(p)?,
        None => Vec::new(),
    };
    out.extend_from_slice(slice);
    if let Some(s) = l["suffix"].as_str() {
        out.extend_from_slice(&B64.decode(s)?);
    }
    Ok(out)
}

fn file_content(entry: &Value) -> Result<Vec<u8>, Err> {
    if let Some(t) = entry["text"].as_str() {
        return Ok(t.as_bytes().to_vec());
    }
    if entry["content"].is_object() {
        let c = &entry["content"];
        let unit = content::bytes(text(c, "seed")?, num(c, "unit")?);
        return Ok(unit.repeat(num(c, "count")?));
    }
    Ok(content::bytes(text(entry, "seed")?, num(entry, "size")?))
}

/// Every block the IPFS half describes, by CID string.
pub fn blocks(ipfs: &Value) -> Result<HashMap<String, Vec<u8>>, Err> {
    let mut out = HashMap::new();
    for (cid, b) in ipfs["blocks"].as_object().ok_or("ipfs.blocks")? {
        out.insert(cid.clone(), B64.decode(b.as_str().ok_or("a block")?)?);
    }
    let mut files: Vec<&Value> = ipfs["files"]
        .as_array()
        .ok_or("ipfs.files")?
        .iter()
        .collect();
    for d in ipfs["directories"].as_array().ok_or("ipfs.directories")? {
        files.extend(d["entries"].as_array().ok_or("entries")?);
    }
    for f in files {
        let data = file_content(f)?;
        for l in f["leaves"].as_array().ok_or("leaves")? {
            out.insert(text(l, "cid")?.to_string(), leaf(&data, l)?);
        }
    }
    Ok(out)
}

/// Rebuilds each CAR in ipfs.kubo; returns how many.
pub fn rebuild_kubo_cars(ipfs: &Value) -> Result<usize, Err> {
    let store = blocks(ipfs)?;
    let mut n = 0;
    for e in ipfs["kubo"].as_array().ok_or("ipfs.kubo")? {
        let body = &e["response"]["body"];
        let Some(c) = body.get("car").filter(|c| c.is_object()) else {
            continue;
        };
        let mut wire = B64.decode(text(c, "header")?)?;
        for cid in c["blocks"].as_array().ok_or("car.blocks")? {
            let cid = cid.as_str().ok_or("a CID")?;
            let block = store
                .get(cid)
                .ok_or_else(|| format!("{}: block {cid} isn't in the vectors", e["id"]))?;
            wire.extend_from_slice(&car::section(&Cid::try_from(cid)?, block));
        }
        wire.extend_from_slice(&B64.decode(text(c, "trailing")?)?);
        let sha = hex::encode(Sha256::digest(&wire));
        if wire.len() != num(body, "length")? || sha != text(body, "sha256")? {
            return Err(format!("{}: the rebuilt CAR differs from Kubo's answer", e["id"]).into());
        }
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    /// The committed vectors alone rebuild every CAR Kubo answered.
    #[test]
    fn every_recorded_car_rebuilds_from_the_vectors() {
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(crate::OUT).unwrap_or_default())
                .unwrap_or_default();
        let n = super::rebuild_kubo_cars(&doc["ipfs"]);
        assert!(matches!(n, Ok(n) if n > 200), "{n:?}");
    }
}
