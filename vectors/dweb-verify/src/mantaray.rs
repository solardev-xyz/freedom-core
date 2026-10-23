//! Mantaray nodes the generator writes itself: the shapes Ant's manifest
//! writer can't make (an obfuscated node, a node larger than one chunk, a
//! node of 64-byte references below a plain root). The layout is the one
//! `ant-retrieval`'s `manifest_writer.rs` serializes and Bee's
//! `pkg/manifest/mantaray/marshal.go` defines; [`self_check`] holds this
//! writer to Ant's on a manifest both can make.

use ant_retrieval::{ManifestFile, build_collection_manifest};

/// The first 31 bytes of `keccak256("mantaray:0.2")`.
fn version_hash() -> [u8; 31] {
    let h = ant_crypto::keccak256(b"mantaray:0.2");
    let mut out = [0u8; 31];
    out.copy_from_slice(&h[..31]);
    out
}

pub const TYPE_VALUE: u8 = 2;
pub const TYPE_EDGE: u8 = 4;
pub const TYPE_PATH_SEPARATOR: u8 = 8;
pub const TYPE_WITH_METADATA: u8 = 16;

pub struct Fork {
    pub node_type: u8,
    pub prefix: Vec<u8>,
    pub child: Vec<u8>,
    /// The metadata's JSON text, unpadded; `None` when the type has no
    /// metadata bit.
    pub metadata: Option<String>,
}

pub struct Node {
    pub obfuscation_key: [u8; 32],
    /// 0 (an empty node), 32 or 64.
    pub ref_size: u8,
    /// The node's entry, `ref_size` bytes (zeros when it has none).
    pub entry: Vec<u8>,
    /// In ascending order of their first byte.
    pub forks: Vec<Fork>,
}

impl Node {
    pub fn marshal(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&self.obfuscation_key);
        p.extend_from_slice(&version_hash());
        p.push(self.ref_size);
        p.extend_from_slice(&self.entry);
        let mut bitmap = [0u8; 32];
        for f in &self.forks {
            let b = f.prefix[0];
            bitmap[usize::from(b) / 8] |= 1 << (b % 8);
        }
        p.extend_from_slice(&bitmap);
        for f in &self.forks {
            p.push(f.node_type);
            p.push(u8::try_from(f.prefix.len()).unwrap_or(u8::MAX));
            p.extend_from_slice(&f.prefix);
            p.extend(std::iter::repeat_n(
                0u8,
                30usize.saturating_sub(f.prefix.len()),
            ));
            p.extend_from_slice(&f.child);
            if let Some(meta) = &f.metadata {
                // Bee's padding, quirk included (see `manifest_writer.rs`).
                let with_size = meta.len() + 2;
                let pad = match with_size.cmp(&32) {
                    std::cmp::Ordering::Less => 32 - with_size,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 32 - with_size % 32,
                };
                let mut padded = meta.as_bytes().to_vec();
                padded.extend(std::iter::repeat_n(b'\n', pad));
                p.extend_from_slice(&u16::try_from(padded.len()).unwrap_or(0).to_be_bytes());
                p.extend_from_slice(&padded);
            }
        }
        if self.obfuscation_key != [0u8; 32] {
            for chunk in p[32..].chunks_mut(32) {
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= self.obfuscation_key[i];
                }
            }
        }
        p
    }
}

/// Fork metadata as Go's `json.Marshal` writes a `map[string]string`: keys
/// sorted, no whitespace. The generator's keys and values need no escapes.
pub fn metadata(pairs: &[(&str, &str)]) -> String {
    let mut sorted: Vec<_> = pairs.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let body: Vec<String> = sorted
        .iter()
        .map(|(k, v)| format!("\"{k}\":\"{v}\""))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// Writes a one-file manifest with both writers and requires equal bytes.
pub fn self_check() -> Result<(), String> {
    let data_ref = [0x11u8; 32];
    let ant = build_collection_manifest(
        &[ManifestFile {
            path: "a.txt".to_string(),
            content_type: Some("text/plain".to_string()),
            data_ref: data_ref.to_vec(),
        }],
        None,
        ant_retrieval::IndexAnchor::ZeroEntry,
    )
    .map_err(|e| e.to_string())?;
    // Ant's writer: the value child (entry only), then the root.
    let child = Node {
        obfuscation_key: [0; 32],
        ref_size: 32,
        entry: data_ref.to_vec(),
        forks: Vec::new(),
    }
    .marshal();
    let (child_addr, _) = ant_crypto::cac_new(&child).ok_or("child chunk")?;
    let root = Node {
        obfuscation_key: [0; 32],
        ref_size: 32,
        entry: vec![0; 32],
        forks: vec![Fork {
            node_type: TYPE_VALUE | TYPE_WITH_METADATA,
            prefix: b"a.txt".to_vec(),
            child: child_addr.to_vec(),
            metadata: Some(metadata(&[
                ("Content-Type", "text/plain"),
                ("Filename", "a.txt"),
            ])),
        }],
    }
    .marshal();
    let (root_addr, _) = ant_crypto::cac_new(&root).ok_or("root chunk")?;
    if root_addr != ant.root {
        return Err(format!(
            "the generator's mantaray writer differs from Ant's: {} != {}",
            hex::encode(root_addr),
            hex::encode(ant.root)
        ));
    }
    Ok(())
}
