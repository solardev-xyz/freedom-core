//! The Swarm half of dweb-verify.json: chunk trees, manifests and feeds made
//! with Ant's own writers (and, for shapes they can't make, by hand), and
//! Ant's gateway's answers to the requests the verifier and the bundled-node
//! parity care about.

use crate::content;
use crate::gateway::{Answer, Ant};
use crate::mantaray::{self, Fork, Node};
use crate::store::{LogFetcher, MemFetcher};
use ant_retrieval::{
    ChunkFetcher, IndexAnchor, JoinOptions, ManifestFile, RawManifestEntry,
    build_collection_manifest, build_entries_manifest, build_feed_manifest,
    build_single_file_manifest, enumerate_chunk_tree, lookup_path, sequence_update_id, split_bytes,
    split_bytes_encrypted_with_keys, split_bytes_with_redundancy,
};
use base64::Engine;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

type Addr = [u8; 32];
type Err = Box<dyn std::error::Error>;

/// The headers Freedom's plans send on every `bzz:` request (fc-dweb
/// `bzz.rs`), so Ant answers as it answers Freedom.
const SWARM_HEADERS: [(&str, &str); 3] = [
    ("swarm-chunk-retrieval-timeout", "30s"),
    ("swarm-redundancy-strategy", "3"),
    ("swarm-redundancy-fallback-mode", "true"),
];

/// The bodies an exchange inlines whole; longer ones are recorded by length
/// and SHA-256.
const INLINE_BODY_MAX: usize = 64 * 1024;

/// The fixed clock: every feed timestamp is counted from it.
pub const CLOCK_UNIX: u64 = 1_760_000_000;

const FILE_SIZES: [usize; 8] = [0, 1, 4095, 4096, 4097, 524_288, 524_289, 67_108_865];

struct Planned {
    case: String,
    method: &'static str,
    path: String,
    headers: Vec<(String, String)>,
    /// The content the body is expected to be a slice of: its seed, its
    /// length, and the offset the body starts at.
    content: Option<(String, usize, usize)>,
    note: &'static str,
}

#[derive(Default)]
pub struct Swarm {
    /// Every chunk the memory network holds: leaves and parities included.
    network: HashMap<Addr, Vec<u8>>,
    /// The chunks written into the file: everything but data leaves and
    /// parities, which a reader rebuilds from the content or never needs.
    recorded: BTreeMap<Addr, Vec<u8>>,
    files: Vec<Value>,
    manifests: Vec<Value>,
    feeds: Vec<Value>,
    shapes: Vec<Value>,
    plans: Vec<Planned>,
}

fn h(a: &[u8]) -> String {
    hex::encode(a)
}

fn swarm_headers(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = SWARM_HEADERS
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    for (k, v) in extra {
        out.push(((*k).to_string(), (*v).to_string()));
    }
    out
}

/// The CAC address of `span ‖ payload` with an arbitrary span.
fn cac_address(span: u64, payload: &[u8]) -> Result<Addr, Err> {
    ant_crypto::bmt_hash_with_span(&span.to_le_bytes(), payload)
        .ok_or_else(|| "payload over 4096 bytes".into())
}

fn cac_wire(span: u64, payload: &[u8]) -> Result<(Addr, Vec<u8>), Err> {
    let addr = cac_address(span, payload)?;
    let mut wire = span.to_le_bytes().to_vec();
    wire.extend_from_slice(payload);
    Ok((addr, wire))
}

/// The range requests for a body of `size` bytes, each with the offset its
/// body starts at, or `None` for an answer with no body of the content.
fn ranges(size: usize) -> Vec<(String, Option<usize>)> {
    let mut out: Vec<(String, Option<usize>)> = Vec::new();
    if size == 0 {
        out.push(("bytes=0-".into(), None));
        out.push(("bytes=0-0".into(), None));
        out.push(("bytes=-1".into(), None));
        return out;
    }
    let last = size - 1;
    out.push(("bytes=0-".into(), Some(0)));
    out.push(("bytes=0-0".into(), Some(0)));
    out.push((format!("bytes={last}-{last}"), Some(last)));
    out.push(("bytes=-1".into(), Some(last)));
    out.push((format!("bytes=-{size}"), Some(0)));
    out.push((format!("bytes=-{}", size + 1), Some(0)));
    out.push((format!("bytes={size}-"), None));
    out.push((format!("bytes=0-{}", size + 10), Some(0)));
    if size >= 4 {
        out.push(("bytes=0-0,2-3".into(), None));
    }
    out.push(("bytes=abc".into(), None));
    if size > 4096 {
        out.push(("bytes=4095-4096".into(), Some(4095)));
        out.push((format!("bytes=4096-{}", (8191).min(last)), Some(4096)));
        out.push(("bytes=4096-".into(), Some(4096)));
    }
    if size > 2 * 1024 * 1024 {
        out.push(("bytes=1048576-2097151".into(), Some(1_048_576)));
        out.push((format!("bytes={}-", size - 4097), Some(size - 4097)));
    }
    out
}

impl Swarm {
    fn hold(&mut self, addr: Addr, wire: Vec<u8>, record: bool) {
        if record {
            self.recorded.insert(addr, wire.clone());
        }
        self.network.insert(addr, wire);
    }

    fn plan(
        &mut self,
        case: &str,
        method: &'static str,
        path: String,
        headers: Vec<(String, String)>,
        content: Option<(String, usize, usize)>,
        note: &'static str,
    ) {
        self.plans.push(Planned {
            case: case.to_string(),
            method,
            path,
            headers,
            content,
            note,
        });
    }

    /// The `/bytes` and bare `/bzz` requests for a data tree of `size`
    /// bytes of `seed`'s content.
    fn plan_raw(&mut self, case: &str, root: Addr, seed: &str, size: usize, full: bool) {
        let c = |from: usize| Some((seed.to_string(), size, from));
        let r = h(&root);
        self.plan(
            case,
            "GET",
            format!("/bytes/{r}"),
            swarm_headers(&[]),
            c(0),
            "",
        );
        self.plan(
            case,
            "HEAD",
            format!("/bytes/{r}"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            c(0),
            "bare root of raw bytes",
        );
        self.plan(
            case,
            "HEAD",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            None,
            "bare root of raw bytes",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/x"),
            swarm_headers(&[]),
            None,
            "a path below raw bytes",
        );
        self.plan(
            case,
            "GET",
            format!("/chunks/{r}"),
            Vec::new(),
            None,
            "the root chunk's wire bytes",
        );
        for (range, from) in ranges(size) {
            if !full && range.contains(',') {
                continue;
            }
            self.plan(
                case,
                "GET",
                format!("/bytes/{r}"),
                swarm_headers(&[("range", &range)]),
                from.and_then(c),
                "",
            );
            if full {
                self.plan(
                    case,
                    "GET",
                    format!("/bzz/{r}/"),
                    swarm_headers(&[("range", &range)]),
                    from.and_then(c),
                    "",
                );
            }
        }
        self.plan(
            case,
            "HEAD",
            format!("/bytes/{r}"),
            swarm_headers(&[("range", "bytes=0-0")]),
            None,
            "Ant ignores Range on a HEAD",
        );
    }

    /// A data tree, with Ant's splitter (and its erasure coding).
    ///
    /// The chunks recorded are the ones Ant's joiner reads for the whole
    /// body, less the content's own leaves: the root, the intermediates,
    /// and any chunk Ant's splitter wrote that isn't a slice of the content.
    /// Parities are never read when nothing is missing, so they stay out.
    async fn add_tree(&mut self, seed: &str, size: usize, level: u8) -> Result<Addr, Err> {
        let data = content::bytes(seed, size);
        let split = split_bytes_with_redundancy(&data, level);
        let id = format!("{seed}-rs{level}");
        let all: HashMap<Addr, Vec<u8>> = split
            .chunks
            .iter()
            .map(|c| (c.address, c.wire.clone()))
            .collect();
        let mem = MemFetcher::new(all.clone());
        let logged = LogFetcher {
            inner: &mem,
            log: std::sync::Mutex::default(),
        };
        let joined = ant_retrieval::join(&logged, &split.root_wire, usize::MAX)
            .await
            .map_err(|e| format!("{id}: {e}"))?;
        let read: Vec<Addr> = logged.log.lock().map(|l| l.clone()).unwrap_or_default();
        let inventory = enumerate_chunk_tree(
            &mem,
            split.root,
            &split.root_wire,
            usize::MAX,
            JoinOptions::default(),
        )
        .await
        .map_err(|e| format!("{id}: {e}"))?;
        // The content's leaves: its 4 KiB slices, as CACs.
        let slices: std::collections::HashSet<Addr> = data
            .chunks(4096)
            .map(|s| cac_address(s.len() as u64, s))
            .collect::<Result<_, _>>()?;
        let mut tree = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut not_slices = Vec::new();
        for addr in std::iter::once(split.root).chain(read) {
            if !seen.insert(addr) {
                continue;
            }
            let wire = all
                .get(&addr)
                .ok_or("a chunk the join read isn't in the split")?;
            let is_slice = slices.contains(&addr) && size > 4096;
            if is_slice {
                continue;
            }
            self.hold(addr, wire.clone(), true);
            tree.push(Value::String(h(&addr)));
            if !inventory.intermediates.contains(&addr) && addr != split.root {
                not_slices.push(Value::String(h(&addr)));
            }
        }
        for c in split.chunks {
            self.network.entry(c.address).or_insert(c.wire);
        }
        let data_leaves = if size <= 4096 {
            1
        } else {
            data.len().div_ceil(4096)
        };
        let mut file = Map::new();
        file.insert("id".into(), json!(id));
        file.insert("seed".into(), json!(seed));
        file.insert("size".into(), json!(size));
        file.insert("redundancy".into(), json!(level));
        file.insert("root".into(), json!(h(&split.root)));
        file.insert("tree".into(), Value::Array(tree));
        file.insert("data_leaves".into(), json!(data_leaves));
        // Every chunk the split wrote that the join didn't read.
        file.insert("parities".into(), json!(all.len() - seen.len()));
        file.insert("joined_equals_content".into(), json!(joined == data));
        if !not_slices.is_empty() {
            file.insert("lone_leaf_wrappers".into(), Value::Array(not_slices));
        }
        self.files.push(Value::Object(file));
        Ok(split.root)
    }

    /// Bee's tree for the same content, where it differs from Ant's: only
    /// where a level of Ant's tree ends in a one-reference wrapper. The
    /// Bee-shaped tree is recorded as a case of its own, and Ant's joiner
    /// must read it as the content.
    async fn bee_shape(&mut self, seed: &str, size: usize, ant_root: Addr) -> Result<(), Err> {
        let data = content::bytes(seed, size);
        let (root, chunks) = crate::bee::split(&data).ok_or("Bee split")?;
        let ant_has_wrapper = self
            .files
            .last()
            .is_some_and(|f| f.get("lone_leaf_wrappers").is_some());
        if root == ant_root {
            if ant_has_wrapper {
                return Err(format!(
                    "{seed}: Bee's tree equals Ant's though Ant's wraps a lone reference"
                )
                .into());
            }
            return Ok(());
        }
        if !ant_has_wrapper {
            return Err(format!(
                "{seed}: the carry-over splitter differs from Ant's with no wrapper to explain it"
            )
            .into());
        }
        let all: HashMap<Addr, Vec<u8>> = chunks.into_iter().collect();
        let root_wire = all.get(&root).cloned().ok_or("Bee root")?;
        let mem = MemFetcher::new(all.clone());
        let logged = LogFetcher {
            inner: &mem,
            log: std::sync::Mutex::default(),
        };
        let joined = ant_retrieval::join(&logged, &root_wire, usize::MAX)
            .await
            .map_err(|e| format!("{seed} (Bee's tree): {e}"))?;
        if joined != data {
            return Err(
                format!("{seed}: Ant's joiner doesn't read Bee's tree as the content").into(),
            );
        }
        let slices: std::collections::HashSet<Addr> = data
            .chunks(4096)
            .map(|s| cac_address(s.len() as u64, s))
            .collect::<Result<_, _>>()?;
        let mut tree = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let read: Vec<Addr> = logged.log.lock().map(|l| l.clone()).unwrap_or_default();
        for addr in std::iter::once(root).chain(read) {
            if !seen.insert(addr) || slices.contains(&addr) {
                continue;
            }
            let wire = all.get(&addr).ok_or("Bee chunk")?;
            self.hold(addr, wire.clone(), true);
            tree.push(Value::String(h(&addr)));
        }
        for (a, w) in all {
            self.network.entry(a).or_insert(w);
        }
        let id = format!("{seed}-rs0-bee");
        self.files.push(json!({
            "id": id,
            "seed": seed,
            "size": size,
            "redundancy": 0,
            "root": h(&root),
            "tree": tree,
            "data_leaves": data.len().div_ceil(4096),
            "parities": 0,
            "joined_equals_content": true,
            "shape": "Bee's: the lone leftover reference carried up unwrapped (hashtrie Sum)",
        }));
        self.plan_raw(&id, root, seed, size, size <= 524_289);
        Ok(())
    }

    async fn files(&mut self) -> Result<(), Err> {
        for size in FILE_SIZES {
            let seed = format!("file-{size}");
            for level in 0..=4u8 {
                let root = self.add_tree(&seed, size, level).await?;
                let case = format!("{seed}-rs{level}");
                if level == 0 {
                    self.bee_shape(&seed, size, root).await?;
                }
                // Every range for the plain tree and the upload default;
                // the whole body and the seeks for the others.
                let full = level <= 1 && size <= 524_289;
                if full || size > 524_289 || level >= 2 {
                    self.plan_raw(&case, root, &seed, size, full);
                }
                // Wrapped in a single-file manifest, as `swarm-cli upload`
                // writes one, for the plain tree and the upload default.
                if level <= 1 {
                    self.single_file_manifest(&case, root, &seed, size)?;
                }
            }
        }
        Ok(())
    }

    fn single_file_manifest(
        &mut self,
        file_case: &str,
        data_ref: Addr,
        seed: &str,
        size: usize,
    ) -> Result<(), Err> {
        let name = "file.bin";
        let m = build_single_file_manifest(name, Some("application/x-test"), data_ref)
            .map_err(|e| e.to_string())?;
        let mut nodes = Vec::new();
        for c in m.chunks {
            nodes.push(Value::String(h(&c.address)));
            self.hold(c.address, c.wire, true);
        }
        let case = format!("{file_case}-manifest");
        self.manifests.push(json!({
            "id": case,
            "root": h(&m.root),
            "writer": "build_single_file_manifest",
            "nodes": nodes,
            "entries": [{ "path": name, "data_ref": h(&data_ref), "content_type": "application/x-test" }],
            "lookups": ["", "file.bin", "/file.bin", "missing"],
        }));
        let r = h(&m.root);
        let c = |from: usize| Some((seed.to_string(), size, from));
        self.plan(
            &case,
            "GET",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            c(0),
            "the index document",
        );
        self.plan(
            &case,
            "GET",
            format!("/bzz/{r}"),
            swarm_headers(&[]),
            c(0),
            "no trailing slash",
        );
        self.plan(
            &case,
            "GET",
            format!("/bzz/{r}/{name}"),
            swarm_headers(&[]),
            c(0),
            "",
        );
        self.plan(
            &case,
            "HEAD",
            format!("/bzz/{r}/{name}"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            &case,
            "GET",
            format!("/bzz/{r}/{name}?state=1"),
            swarm_headers(&[]),
            c(0),
            "a query",
        );
        self.plan(
            &case,
            "GET",
            format!("/bzz/{r}/missing"),
            swarm_headers(&[]),
            None,
            "",
        );
        let etag = format!("\"{}\"", h(&data_ref));
        self.plan(
            &case,
            "GET",
            format!("/bzz/{r}/{name}"),
            swarm_headers(&[("if-none-match", &etag)]),
            c(0),
            "Ant ignores If-None-Match",
        );
        self.plan(
            &case,
            "GET",
            format!("/bzz/{r}/{name}"),
            swarm_headers(&[("if-none-match", "*")]),
            c(0),
            "Ant ignores If-None-Match",
        );
        if size > 0 {
            self.plan(
                &case,
                "GET",
                format!("/bzz/{r}/{name}"),
                swarm_headers(&[("range", "bytes=0-0"), ("if-range", &etag)]),
                c(0),
                "Ant ignores If-Range",
            );
            self.plan(
                &case,
                "GET",
                format!("/bzz/{r}/{name}"),
                swarm_headers(&[("range", "bytes=0-0"), ("if-range", "\"other\"")]),
                c(0),
                "Ant ignores If-Range",
            );
            for (range, from) in ranges(size) {
                self.plan(
                    &case,
                    "GET",
                    format!("/bzz/{r}/{name}"),
                    swarm_headers(&[("range", &range)]),
                    from.and_then(c),
                    "",
                );
            }
            self.plan(
                &case,
                "HEAD",
                format!("/bzz/{r}/{name}"),
                swarm_headers(&[("range", "bytes=0-0")]),
                None,
                "Ant ignores Range on a HEAD",
            );
        }
        Ok(())
    }

    /// Small files for the sites, as data trees of their own.
    fn site_file(&mut self, seed: &str, size: usize) -> Result<Addr, Err> {
        let data = content::bytes(seed, size);
        let split = split_bytes(&data);
        // Recorded: the root and the intermediates. A larger file's leaves
        // are its content's slices, which a reader rebuilds.
        let slices: std::collections::HashSet<Addr> = if size > 4096 {
            data.chunks(4096)
                .map(|s| cac_address(s.len() as u64, s))
                .collect::<Result<_, _>>()?
        } else {
            std::collections::HashSet::new()
        };
        for c in split.chunks {
            let record = c.address == split.root || !slices.contains(&c.address);
            self.hold(c.address, c.wire, record);
        }
        Ok(split.root)
    }

    fn record_manifest(
        &mut self,
        id: &str,
        writer: &str,
        root: Addr,
        chunks: Vec<ant_retrieval::SplitChunk>,
        entries: Vec<Value>,
        lookups: &[&str],
    ) {
        let mut nodes = Vec::new();
        for c in chunks {
            nodes.push(Value::String(h(&c.address)));
            self.hold(c.address, c.wire, true);
        }
        self.manifests.push(json!({
            "id": id,
            "root": h(&root),
            "writer": writer,
            "nodes": nodes,
            "entries": entries,
            "lookups": lookups,
        }));
    }

    async fn sites(&mut self) -> Result<(), Err> {
        // (path, seed, size, content type)
        let files: [(&str, &str, usize, &str); 12] = [
            ("index.html", "site-index", 300, "text/html; charset=utf-8"),
            ("error.html", "site-error", 200, "text/html"),
            ("style.css", "site-style", 5000, "text/css"),
            ("docs/page.html", "site-docs-page", 1000, "text/html"),
            ("docs/sub/x.txt", "site-docs-x", 10, "text/plain"),
            ("a", "site-a", 3, "text/plain"),
            ("ab", "site-ab", 4, "text/plain"),
            ("abc/d", "site-abc-d", 5, "text/plain"),
            (
                "a-name-that-is-longer-than-one-fork-can-hold-in-thirty-bytes.txt",
                "site-long",
                6,
                "text/plain",
            ),
            (
                "ünï/çødé.txt",
                "site-unicode",
                7,
                "text/plain; charset=utf-8",
            ),
            ("日本/ファイル.txt", "site-cjk", 8, "text/plain"),
            ("img/photo.jpg", "site-photo", 20_000, "image/jpeg"),
        ];
        let mut manifest_files = Vec::new();
        let mut entries = Vec::new();
        let mut raw_entries = Vec::new();
        for (path, seed, size, ctype) in files {
            let r = self.site_file(seed, size)?;
            manifest_files.push(ManifestFile {
                path: path.to_string(),
                content_type: Some(ctype.to_string()),
                data_ref: r.to_vec(),
            });
            entries.push(json!({ "path": path, "data_ref": h(&r), "content_type": ctype, "seed": seed, "size": size }));
            let base = path.rsplit('/').next().unwrap_or(path);
            let mut md = BTreeMap::new();
            md.insert("Content-Type".to_string(), ctype.to_string());
            md.insert("Filename".to_string(), base.to_string());
            raw_entries.push(RawManifestEntry {
                path: path.to_string(),
                reference: r,
                metadata: md,
            });
        }
        let lookups = [
            "",
            "index.html",
            "docs",
            "docs/",
            "docs/page.html",
            "docs/sub",
            "docs/sub/x.txt",
            "a",
            "ab",
            "abc",
            "abc/d",
            "a-name-that-is-longer-than-one-fork-can-hold-in-thirty-bytes.txt",
            "ünï/çødé.txt",
            "日本/ファイル.txt",
            "missing",
            "docs/missing",
        ];

        // A: Bee's directory upload (dirs.go): an index document, a zero
        // entry on the "/" fork.
        let a =
            build_collection_manifest(&manifest_files, Some("index.html"), IndexAnchor::ZeroEntry)
                .map_err(|e| e.to_string())?;
        let a_root = a.root;
        self.record_manifest(
            "site-a",
            "build_collection_manifest (index.html, ZeroEntry)",
            a.root,
            a.chunks,
            entries.clone(),
            &lookups,
        );
        self.plan_site("site-a", a_root, &files);

        // B: the same files with an error document too, as raw entries,
        // the "/" fork's metadata naming both documents.
        let mut b_entries = raw_entries.clone();
        let mut root_md = BTreeMap::new();
        root_md.insert(
            "website-index-document".to_string(),
            "index.html".to_string(),
        );
        root_md.insert(
            "website-error-document".to_string(),
            "error.html".to_string(),
        );
        b_entries.push(RawManifestEntry {
            path: "/".to_string(),
            reference: [0u8; 32],
            metadata: root_md,
        });
        let b = build_entries_manifest(&b_entries).map_err(|e| e.to_string())?;
        let b_root = b.root;
        self.record_manifest(
            "site-b",
            "build_entries_manifest (index and error documents)",
            b.root,
            b.chunks,
            entries.clone(),
            &lookups,
        );
        self.plan_site("site-b", b_root, &files);

        // C: no index document at all.
        let c = build_collection_manifest(&manifest_files, None, IndexAnchor::ZeroEntry)
            .map_err(|e| e.to_string())?;
        let c_root = c.root;
        self.record_manifest(
            "site-c",
            "build_collection_manifest (no index document)",
            c.root,
            c.chunks,
            entries,
            &["", "index.html", "docs", "missing"],
        );
        let r = h(&c_root);
        self.plan(
            "site-c",
            "GET",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            None,
            "no index document",
        );
        self.plan(
            "site-c",
            "GET",
            format!("/bzz/{r}/missing"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            "site-c",
            "GET",
            format!("/bzz/{r}/docs"),
            swarm_headers(&[]),
            None,
            "",
        );

        self.crafted(a_root).await?;
        Ok(())
    }

    fn plan_site(&mut self, case: &str, root: Addr, files: &[(&str, &str, usize, &str)]) {
        let r = h(&root);
        let find = |p: &str| {
            files
                .iter()
                .find(|f| f.0 == p)
                .map(|f| (f.1.to_string(), f.2, 0))
        };
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            find("index.html"),
            "the index document",
        );
        self.plan(
            case,
            "HEAD",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}"),
            swarm_headers(&[]),
            find("index.html"),
            "no trailing slash",
        );
        for (path, ..) in files {
            let enc = percent(path);
            self.plan(
                case,
                "GET",
                format!("/bzz/{r}/{enc}"),
                swarm_headers(&[]),
                find(path),
                "",
            );
            self.plan(
                case,
                "HEAD",
                format!("/bzz/{r}/{enc}"),
                swarm_headers(&[]),
                None,
                "",
            );
        }
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/docs"),
            swarm_headers(&[]),
            None,
            "a directory: a 308 to docs/",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/docs?state=1"),
            swarm_headers(&[]),
            None,
            "the 308 keeps the query",
        );
        self.plan(
            case,
            "HEAD",
            format!("/bzz/{r}/docs"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/docs/"),
            swarm_headers(&[]),
            None,
            "a directory with no index document of its own",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/docs/sub"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/abc"),
            swarm_headers(&[]),
            None,
            "a prefix that is a directory",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/missing"),
            swarm_headers(&[]),
            find("error.html"),
            "a miss",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/docs/missing"),
            swarm_headers(&[]),
            find("error.html"),
            "a miss below a directory",
        );
        self.plan(
            case,
            "HEAD",
            format!("/bzz/{r}/missing"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/style.css"),
            swarm_headers(&[("range", "bytes=4096-")]),
            Some(("site-style".into(), 5000, 4096)),
            "",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/img/photo.jpg"),
            swarm_headers(&[("range", "bytes=-100")]),
            Some(("site-photo".into(), 20_000, 19_900)),
            "",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/index.html?x=%2F"),
            swarm_headers(&[]),
            find("index.html"),
            "a query",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}/docs%2Fpage.html"),
            swarm_headers(&[]),
            None,
            "an encoded separator",
        );
        self.plan(
            case,
            "GET",
            format!("/bzz/{r}//index.html"),
            swarm_headers(&[]),
            None,
            "an empty segment",
        );
    }

    /// The shapes Ant's writer can't make.
    async fn crafted(&mut self, site_a: Addr) -> Result<(), Err> {
        // An obfuscated copy of site A's root node: the key from a seed, the
        // rest XORed with it.
        let a_root = self.network.get(&site_a).cloned().ok_or("site A's root")?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&content::bytes("obfuscation-key", 32));
        let mut obf = key.to_vec();
        for (i, b) in a_root[8 + 32..].iter().enumerate() {
            obf.push(b ^ key[i % 32]);
        }
        let (addr, wire) = cac_wire(obf.len() as u64, &obf)?;
        self.hold(addr, wire, true);
        self.manifests.push(json!({
            "id": "obfuscated-root",
            "root": h(&addr),
            "writer": "site A's root node, obfuscated with the key content(\"obfuscation-key\", 32)",
            "nodes": [h(&addr)],
            "entries": [],
            "lookups": ["", "index.html", "docs/page.html", "missing"],
        }));
        let r = h(&addr);
        self.plan(
            "obfuscated-root",
            "GET",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            Some(("site-index".into(), 300, 0)),
            "",
        );
        self.plan(
            "obfuscated-root",
            "GET",
            format!("/bzz/{r}/docs/page.html"),
            swarm_headers(&[]),
            Some(("site-docs-page".into(), 1000, 0)),
            "",
        );

        // A root node over one chunk: 160 forks with metadata, stored as a
        // file, so the node is a chunk tree of its own.
        let target = self.site_file("big-node-target", 11)?;
        let mut forks = Vec::new();
        for i in 0..160u32 {
            // First bytes from 0x21 upwards, each fork its own byte.
            let first = u8::try_from(0x21 + i).unwrap_or(0xff);
            let mut prefix = vec![first];
            prefix.extend_from_slice(format!("-entry-{i:03}").as_bytes());
            let leaf = Node {
                obfuscation_key: [0; 32],
                ref_size: 32,
                entry: target.to_vec(),
                forks: Vec::new(),
            }
            .marshal();
            let (leaf_addr, leaf_wire) = cac_wire(leaf.len() as u64, &leaf)?;
            self.hold(leaf_addr, leaf_wire, true);
            forks.push(Fork {
                node_type: mantaray::TYPE_VALUE | mantaray::TYPE_WITH_METADATA,
                prefix,
                child: leaf_addr.to_vec(),
                metadata: Some(mantaray::metadata(&[
                    ("Content-Type", "text/plain"),
                    ("Filename", "same.txt"),
                ])),
            });
        }
        let big = Node {
            obfuscation_key: [0; 32],
            ref_size: 32,
            entry: vec![0; 32],
            forks,
        }
        .marshal();
        let split = split_bytes(&big);
        let mut nodes = Vec::new();
        for c in split.chunks {
            nodes.push(Value::String(h(&c.address)));
            self.hold(c.address, c.wire, true);
        }
        self.manifests.push(json!({
            "id": "big-node",
            "root": h(&split.root),
            "writer": "the generator: a root node of 160 forks with metadata, stored as a file",
            "node_bytes": big.len(),
            "nodes": nodes,
            "entries": [],
            "lookups": ["!-entry-000", "\u{20}", "\u{a0}-entry-127", "missing"],
        }));
        let r = h(&split.root);
        self.plan(
            "big-node",
            "GET",
            format!("/bzz/{r}/%21-entry-000"),
            swarm_headers(&[]),
            Some(("big-node-target".into(), 11, 0)),
            "",
        );
        self.plan(
            "big-node",
            "GET",
            format!("/bzz/{r}/missing"),
            swarm_headers(&[]),
            None,
            "",
        );

        // Encrypted content below a plain root: a plain node whose
        // references are 64 bytes, reached through a 32-byte fork.
        let data = content::bytes("encrypted-file", 6000);
        let enc = split_bytes_encrypted_with_keys(&data, 0, key_stream("encrypted-file"));
        for c in &enc.chunks {
            self.hold(c.address, c.wire.clone(), true);
        }
        // The value node holds the file's 64-byte reference, and is itself
        // stored encrypted, as an encrypted manifest stores its nodes, so
        // the fork names it by a 64-byte reference too.
        let value = Node {
            obfuscation_key: [0; 32],
            ref_size: 64,
            entry: enc.root_ref.to_vec(),
            forks: Vec::new(),
        }
        .marshal();
        let value_split =
            split_bytes_encrypted_with_keys(&value, 0, key_stream("encrypted-value-node"));
        for c in &value_split.chunks {
            self.hold(c.address, c.wire.clone(), true);
        }
        let child = Node {
            obfuscation_key: [0; 32],
            ref_size: 64,
            entry: vec![0; 64],
            forks: vec![Fork {
                node_type: mantaray::TYPE_VALUE | mantaray::TYPE_WITH_METADATA,
                prefix: b"secret.bin".to_vec(),
                child: value_split.root_ref.to_vec(),
                metadata: Some(mantaray::metadata(&[
                    ("Content-Type", "application/octet-stream"),
                    ("Filename", "secret.bin"),
                ])),
            }],
        }
        .marshal();
        let (child_addr, child_wire) = cac_wire(child.len() as u64, &child)?;
        self.hold(child_addr, child_wire, true);
        let root = Node {
            obfuscation_key: [0; 32],
            ref_size: 32,
            entry: vec![0; 32],
            forks: vec![Fork {
                node_type: mantaray::TYPE_EDGE | mantaray::TYPE_PATH_SEPARATOR,
                prefix: b"enc/".to_vec(),
                child: child_addr.to_vec(),
                metadata: None,
            }],
        }
        .marshal();
        let (root_addr, root_wire) = cac_wire(root.len() as u64, &root)?;
        self.hold(root_addr, root_wire, true);
        self.manifests.push(json!({
            "id": "encrypted-below-plain-root",
            "root": h(&root_addr),
            "writer": "the generator: a plain root whose fork enc/ leads to a node of 64-byte references",
            "nodes": [h(&root_addr), h(&child_addr)],
            "entries": [{ "path": "enc/secret.bin", "data_ref": h(&enc.root_ref), "seed": "encrypted-file", "size": 6000, "keys": "key_stream(\"encrypted-file\")" }],
            "lookups": ["enc/secret.bin", "enc/", "missing"],
        }));
        let r = h(&root_addr);
        self.plan(
            "encrypted-below-plain-root",
            "GET",
            format!("/bzz/{r}/enc/secret.bin"),
            swarm_headers(&[]),
            Some(("encrypted-file".into(), 6000, 0)),
            "an encrypted reference inside a walk",
        );
        Ok(())
    }

    async fn feed_set(&mut self, site_a: Addr, site_b: Addr) -> Result<(), Err> {
        let secret = owner_secret("feed-owner")?;
        let owner = owner_address(&secret)?;
        // v1: three updates, each naming a site or a file.
        let small = self.site_file("feed-file", 1234)?;
        let topic_v1 = ant_crypto::keccak256(b"topic-v1");
        let refs = [site_a, site_b, site_a];
        let mut updates = Vec::new();
        for (i, r) in refs.iter().enumerate() {
            let mut payload = (CLOCK_UNIX + i as u64).to_be_bytes().to_vec();
            payload.extend_from_slice(r);
            updates.push(self.feed_update(
                &secret,
                &owner,
                &topic_v1,
                i as u64,
                &payload,
                "v1",
                h(r),
            )?);
        }
        self.feed_manifest("feed-v1", &owner, &topic_v1, updates)?;

        // v2: the update wraps the content's root chunk itself.
        let topic_v2 = ant_crypto::keccak256(b"topic-v2");
        let mut updates = Vec::new();
        for (i, r) in [site_b, small].iter().enumerate() {
            let wire = self.network.get(r).cloned().ok_or("v2 content root")?;
            let span = u64::from_le_bytes(wire[..8].try_into().map_err(|_| "span")?);
            updates.push(self.feed_update_wrapping(
                &secret,
                &owner,
                &topic_v2,
                i as u64,
                span,
                &wire[8..],
                "v2",
                h(r),
            )?);
        }
        self.feed_manifest("feed-v2", &owner, &topic_v2, updates)?;

        // v2 again, its latest update a manifest: the answers carry
        // swarm-feed-resolved-version v2.
        let topic_v2m = ant_crypto::keccak256(b"topic-v2-manifest");
        let mut updates = Vec::new();
        for (i, r) in [small, site_b].iter().enumerate() {
            let wire = self.network.get(r).cloned().ok_or("v2 content root")?;
            let span = u64::from_le_bytes(wire[..8].try_into().map_err(|_| "span")?);
            updates.push(self.feed_update_wrapping(
                &secret,
                &owner,
                &topic_v2m,
                i as u64,
                span,
                &wire[8..],
                "v2",
                h(r),
            )?);
        }
        self.feed_manifest("feed-v2-manifest", &owner, &topic_v2m, updates)?;

        // An 80-byte v1 update: its reference is 64 bytes, encrypted.
        let data = content::bytes("feed-encrypted-file", 3000);
        let enc = split_bytes_encrypted_with_keys(&data, 0, key_stream("feed-encrypted-file"));
        for c in &enc.chunks {
            self.hold(c.address, c.wire.clone(), true);
        }
        let topic_enc = ant_crypto::keccak256(b"topic-encrypted");
        let mut payload = CLOCK_UNIX.to_be_bytes().to_vec();
        payload.extend_from_slice(&enc.root_ref);
        let u = self.feed_update(
            &secret,
            &owner,
            &topic_enc,
            0,
            &payload,
            "v1",
            h(&enc.root_ref),
        )?;
        self.feed_manifest("feed-encrypted", &owner, &topic_enc, vec![u])?;

        // A feed with no update at all.
        let topic_empty = ant_crypto::keccak256(b"topic-empty");
        self.feed_manifest("feed-empty", &owner, &topic_empty, Vec::new())?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn feed_update(
        &mut self,
        secret: &[u8; 32],
        owner: &[u8; 20],
        topic: &[u8; 32],
        index: u64,
        payload: &[u8],
        version: &str,
        names: String,
    ) -> Result<Value, Err> {
        self.feed_update_wrapping(
            secret,
            owner,
            topic,
            index,
            payload.len() as u64,
            payload,
            version,
            names,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn feed_update_wrapping(
        &mut self,
        secret: &[u8; 32],
        owner: &[u8; 20],
        topic: &[u8; 32],
        index: u64,
        span: u64,
        payload: &[u8],
        version: &str,
        names: String,
    ) -> Result<Value, Err> {
        let id = sequence_update_id(topic, index);
        let inner = cac_address(span, payload)?;
        let mut sig_data = id.to_vec();
        sig_data.extend_from_slice(&inner);
        let sig = ant_crypto::sign_handshake_data(secret, &ant_crypto::keccak256(&sig_data))
            .map_err(|e| e.to_string())?;
        let mut wire = id.to_vec();
        wire.extend_from_slice(&sig);
        wire.extend_from_slice(&span.to_le_bytes());
        wire.extend_from_slice(payload);
        let mut addr_input = id.to_vec();
        addr_input.extend_from_slice(owner);
        let addr = ant_crypto::keccak256(&addr_input);
        if !ant_crypto::soc_valid(&addr, &wire) {
            return Err("a feed update the generator signed doesn't validate".into());
        }
        self.hold(addr, wire, true);
        Ok(
            json!({ "index": index, "address": h(&addr), "id": h(&id), "version": version, "names": names }),
        )
    }

    fn feed_manifest(
        &mut self,
        id: &str,
        owner: &[u8; 20],
        topic: &[u8; 32],
        updates: Vec<Value>,
    ) -> Result<(), Err> {
        let m = build_feed_manifest(owner, topic).map_err(|e| e.to_string())?;
        let mut nodes = Vec::new();
        for c in m.chunks {
            nodes.push(Value::String(h(&c.address)));
            self.hold(c.address, c.wire, true);
        }
        let r = h(&m.root);
        self.feeds.push(json!({
            "id": id,
            "owner": h(owner),
            "topic": h(topic),
            "owner_secret": "keccak256(\"feed-owner\")",
            "manifest": r,
            "manifest_nodes": nodes,
            "updates": updates,
        }));
        let o = h(owner);
        let t = h(topic);
        self.plan(
            id,
            "GET",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            id,
            "HEAD",
            format!("/bzz/{r}/"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            id,
            "GET",
            format!("/bzz/{r}/"),
            swarm_headers(&[("range", "bytes=0-9")]),
            None,
            "",
        );
        self.plan(
            id,
            "GET",
            format!("/bzz/{r}/"),
            swarm_headers(&[("range", "bytes=100000-")]),
            None,
            "an unsatisfiable range through a feed",
        );
        self.plan(
            id,
            "GET",
            format!("/bzz/{r}/docs/page.html"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            id,
            "GET",
            format!("/bzz/{r}/docs"),
            swarm_headers(&[]),
            None,
            "a 308 through a feed",
        );
        self.plan(
            id,
            "GET",
            format!("/bzz/{r}/missing"),
            swarm_headers(&[]),
            None,
            "",
        );
        self.plan(
            id,
            "GET",
            format!("/feeds/{o}/{t}"),
            vec![("swarm-only-root-chunk".into(), "true".into())],
            None,
            "what the verifier asks",
        );
        self.plan(id, "GET", format!("/feeds/{o}/{t}"), Vec::new(), None, "");
        Ok(())
    }

    /// Leaves Ant accepts that a simple reader wouldn't.
    fn shapes(&mut self) -> Result<(), Err> {
        // A two-leaf file of 4096 + 60 bytes whose second leaf's payload
        // is 100 bytes: Ant serves the 60 its parent gives it.
        let tail = content::bytes("surplus-tail", 100);
        let first = content::bytes("surplus-head", 4096);
        let (l0, w0) = cac_wire(4096, &first)?;
        self.hold(l0, w0, false);
        for (id, span, note) in [
            (
                "surplus-payload",
                100u64,
                "the last leaf's span and payload are 100 bytes; its parent gives it 60",
            ),
            (
                "span-below-logical",
                50,
                "the last leaf's span is 50, its payload 100; its parent gives it 60",
            ),
            (
                "span-full-block",
                4096,
                "the last leaf's span claims 4096, its payload is 100; its parent gives it 60",
            ),
        ] {
            let (l1, w1) = cac_wire(span, &tail)?;
            self.hold(l1, w1.clone(), true);
            let mut refs = l0.to_vec();
            refs.extend_from_slice(&l1);
            let (root, rw) = cac_wire(4096 + 60, &refs)?;
            self.hold(root, rw, true);
            self.shapes.push(json!({
                "id": id,
                "root": h(&root),
                "note": note,
                "leaves": [
                    { "address": h(&l0), "seed": "surplus-head", "size": 4096 },
                    { "address": h(&l1), "span": span, "seed": "surplus-tail", "size": 100 },
                ],
            }));
            let r = h(&root);
            self.plan(
                id,
                "GET",
                format!("/bytes/{r}"),
                swarm_headers(&[]),
                None,
                note,
            );
            self.plan(
                id,
                "GET",
                format!("/bytes/{r}"),
                swarm_headers(&[("range", "bytes=4096-")]),
                Some(("surplus-tail".into(), 100, 0)),
                note,
            );
            self.plan(
                id,
                "GET",
                format!("/bytes/{r}"),
                swarm_headers(&[("range", "bytes=4150-4200")]),
                Some(("surplus-tail".into(), 100, 54)),
                note,
            );
            self.plan(
                id,
                "GET",
                format!("/bzz/{r}/"),
                swarm_headers(&[]),
                None,
                note,
            );
        }
        Ok(())
    }

    async fn run(&mut self) -> Result<Vec<Value>, Err> {
        let ant = Ant::new(Arc::new(MemFetcher::new(self.network.clone())));
        let mut out = Vec::new();
        let plans = std::mem::take(&mut self.plans);
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut contents: HashMap<String, Vec<u8>> = HashMap::new();
        for p in plans {
            let answer: Answer = ant
                .send(p.method, &p.path, &p.headers)
                .await
                .map_err(|e| format!("{} {}: {e}", p.method, p.path))?;
            // Ant draws a random multipart boundary: the file writes it as
            // `{boundary}`, in the header and the body alike.
            let mut answer = answer;
            if let Some(boundary) = answer
                .headers
                .iter()
                .find(|(k, _)| k == "content-type")
                .and_then(|(_, v)| v.strip_prefix("multipart/byteranges; boundary="))
                .map(str::to_string)
            {
                for (_, v) in &mut answer.headers {
                    *v = v.replace(&boundary, "{boundary}");
                }
                answer.body = replace_bytes(&answer.body, boundary.as_bytes(), b"{boundary}");
            }
            let n = seen.entry(p.case.clone()).or_insert(0);
            *n += 1;
            let id = format!("{}#{}", p.case, n);
            let body = describe_body(&answer.body, p.content.as_ref(), &mut contents);
            let mut req = Map::new();
            req.insert("method".into(), json!(p.method));
            req.insert("path".into(), json!(p.path));
            req.insert(
                "headers".into(),
                Value::Array(p.headers.iter().map(|(k, v)| json!([k, v])).collect()),
            );
            let mut ex = Map::new();
            ex.insert("id".into(), json!(id));
            ex.insert("case".into(), json!(p.case));
            if !p.note.is_empty() {
                ex.insert("note".into(), json!(p.note));
            }
            ex.insert("request".into(), Value::Object(req));
            ex.insert(
                "response".into(),
                json!({
                    "status": answer.status,
                    "headers": answer.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                    "body": body,
                }),
            );
            out.push(Value::Object(ex));
        }
        Ok(out)
    }

    /// Ant's `lookup_path` answer for each manifest's listed paths.
    async fn resolve_lookups(&mut self) -> Result<(), Err> {
        let fetcher = MemFetcher::new(self.network.clone());
        for m in &mut self.manifests {
            let root = hex::decode(m["root"].as_str().unwrap_or_default())?;
            let paths: Vec<String> = m["lookups"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let mut answers = Vec::new();
            for p in paths {
                let answer = match lookup_path(&fetcher as &dyn ChunkFetcher, &root, &p).await {
                    Ok(r) => {
                        let md: BTreeMap<_, _> = r.metadata.into_iter().collect();
                        json!({
                            "path": p,
                            "data_ref": h(&r.data_ref),
                            "content_type": r.content_type,
                            "metadata": md,
                            "feed": r.feed.map(|f| json!({ "index": f.index, "v2": f.v2 })),
                        })
                    }
                    Err(e) => json!({ "path": p, "error": e.to_string() }),
                };
                answers.push(answer);
            }
            m["lookups"] = Value::Array(answers);
        }
        Ok(())
    }
}

fn replace_bytes(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

fn describe_body(
    body: &[u8],
    content: Option<&(String, usize, usize)>,
    cache: &mut HashMap<String, Vec<u8>>,
) -> Value {
    if body.is_empty() {
        return json!({ "length": 0 });
    }
    if let Some((seed, size, from)) = content {
        let data = cache
            .entry(seed.clone())
            .or_insert_with(|| content::bytes(seed, *size));
        if data.get(*from..*from + body.len()) == Some(body) {
            return json!({ "content": { "seed": seed, "from": from, "length": body.len() } });
        }
    }
    if body.len() <= INLINE_BODY_MAX {
        return json!({ "base64": base64::engine::general_purpose::STANDARD.encode(body) });
    }
    json!({ "length": body.len(), "sha256": hex::encode(Sha256::digest(body)) })
}

/// Percent-encodes a path's bytes outside the unreserved set and `/`, as
/// an HTTP client sends a UTF-8 path.
fn percent(path: &str) -> String {
    let mut out = String::new();
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The chunk keys of an encrypted split, in Ant's chunk-write order: key i
/// is `keccak256(label ‖ u32_be(i))`. Ant pads the ciphertext with zeros
/// when keys are injected.
pub fn key_stream(label: &str) -> impl FnMut() -> [u8; 32] + use<> {
    let label = label.as_bytes().to_vec();
    let mut i: u32 = 0;
    move || {
        let mut input = label.clone();
        input.extend_from_slice(&i.to_be_bytes());
        i += 1;
        ant_crypto::keccak256(&input)
    }
}

fn owner_secret(label: &str) -> Result<[u8; 32], Err> {
    Ok(ant_crypto::keccak256(label.as_bytes()))
}

fn owner_address(secret: &[u8; 32]) -> Result<[u8; 20], Err> {
    let sk = k256::ecdsa::SigningKey::from_bytes(secret.into()).map_err(|e| e.to_string())?;
    Ok(ant_crypto::ethereum_address_from_public_key(
        sk.verifying_key(),
    ))
}

/// Builds the Swarm section.
pub async fn build() -> Result<Value, Err> {
    mantaray::self_check()?;
    let mut s = Swarm::default();
    s.files().await?;
    s.sites().await?;
    let site_a = s
        .manifests
        .iter()
        .find(|m| m["id"] == "site-a")
        .and_then(|m| m["root"].as_str())
        .map(hex::decode)
        .ok_or("site A")??;
    let site_b = s
        .manifests
        .iter()
        .find(|m| m["id"] == "site-b")
        .and_then(|m| m["root"].as_str())
        .map(hex::decode)
        .ok_or("site B")??;
    let site_a: Addr = site_a.try_into().map_err(|_| "site A root")?;
    let site_b: Addr = site_b.try_into().map_err(|_| "site B root")?;
    s.feed_set(site_a, site_b).await?;
    s.shapes()?;
    s.resolve_lookups().await?;
    let exchanges = s.run().await?;
    let chunks: Map<String, Value> = s
        .recorded
        .iter()
        .map(|(a, w)| {
            (
                h(a),
                Value::String(base64::engine::general_purpose::STANDARD.encode(w)),
            )
        })
        .collect();
    Ok(json!({
        "files": s.files,
        "manifests": s.manifests,
        "feeds": s.feeds,
        "shapes": s.shapes,
        "chunks": chunks,
        "exchanges": exchanges,
    }))
}
