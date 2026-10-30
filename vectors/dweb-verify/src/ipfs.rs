//! The IPFS half of dweb-verify.json: DAGs Kubo writes from seeded content,
//! the trustless answers Kubo's gateway gives for them (CARs and raw
//! blocks), freedom-ipfs's `GatewayCore`'s answers over the same blocks
//! (the parity target), and IPNS records with freedom-ipfs's verdicts.

use crate::car;
use crate::content;
use crate::ipns::{self, Key, Spec};
use crate::kubo::Kubo;
use base64::Engine;
use cid::Cid;
use freedom_ipfs_core::{Block, BlockProvider};
use freedom_ipfs_gateway::{GatewayConfig, GatewayCore, NativeRequest, NativeRequestHeader};
use freedom_ipfs_namesys::{NameResolver, NamesysError};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type Err = Box<dyn std::error::Error>;

/// A file of a directory fixture: its path, seed and size.
type TreeFile = (String, String, usize);

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

const CAR_ACCEPT: &str = "application/vnd.ipld.car; version=1; order=dfs; dups=y";
const RAW_ACCEPT: &str = "application/vnd.ipld.raw";
const RECORD_ACCEPT: &str = "application/vnd.ipfs.ipns-record";
/// Chromium's navigation `Accept`, which `small_text` and the error page key on.
const NAV_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";

const INLINE_BODY_MAX: usize = 64 * 1024;
const CHUNK: usize = 262_144;

const FILE_SIZES: [usize; 6] = [0, 1, 262_143, 262_144, 262_145, 10 * 1024 * 1024];

/// `ipfs add` flags, by the two layouts 0009 names.
const V0: [&str; 4] = [
    "--cid-version=0",
    "--raw-leaves=false",
    "--chunker=size-262144",
    "--hash=sha2-256",
];
const V1: [&str; 4] = [
    "--cid-version=1",
    "--raw-leaves=true",
    "--chunker=size-262144",
    "--hash=sha2-256",
];

/// Blocks by CID, as a store that holds exactly these would answer. An
/// identity CID's block is its digest, which any provider can give.
pub struct MemProvider(pub HashMap<Cid, Vec<u8>>);

impl BlockProvider for MemProvider {
    fn get_block(&self, cid: &Cid) -> freedom_ipfs_core::Result<Option<Block>> {
        if cid.hash().code() == 0x00 {
            return Ok(Some(Block::unchecked(*cid, cid.hash().digest().to_vec())));
        }
        Ok(self.0.get(cid).map(|d| Block::unchecked(*cid, d.clone())))
    }
}

/// The names a resolver that verified these records would resolve.
pub struct Names(pub HashMap<String, String>);

#[async_trait::async_trait]
impl NameResolver for Names {
    async fn resolve_name(&self, name: &str) -> freedom_ipfs_namesys::Result<String> {
        self.0
            .get(name)
            .cloned()
            .ok_or_else(|| NamesysError::NotFound(name.to_string()))
    }
}

/// What a body is expected to be: a slice of seeded content.
#[derive(Clone)]
struct Expect {
    seed: String,
    size: usize,
    from: usize,
}

#[derive(Default)]
struct Ipfs {
    /// Every block, leaves included, for the providers.
    all: HashMap<Cid, Vec<u8>>,
    /// The blocks written into the file: all but the content's leaves.
    recorded: BTreeMap<String, Vec<u8>>,
    files: Vec<Value>,
    directories: Vec<Value>,
    identity: Vec<Value>,
    records: Vec<Value>,
    native: Vec<Value>,
    kubo: Vec<Value>,
    names: HashMap<String, String>,
    contents: HashMap<String, Vec<u8>>,
}

fn work_dir() -> Result<PathBuf, Err> {
    let d = std::env::temp_dir().join(format!("dweb-verify-fixtures-{}", std::process::id()));
    if d.exists() {
        std::fs::remove_dir_all(&d)?;
    }
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

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

fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

impl Ipfs {
    /// A file's DAG: the leaves, each a slice of the content, and the other
    /// blocks, which are recorded whole.
    fn describe_dag(&mut self, root: &Cid, data: &[u8]) -> Result<(Vec<Value>, Vec<Value>), Err> {
        let mut leaves = Vec::new();
        let mut nodes = Vec::new();
        let mut offset = 0usize;
        let mut stack = vec![*root];
        while let Some(cid) = stack.pop() {
            let block = self
                .all
                .get(&cid)
                .cloned()
                .ok_or_else(|| format!("block {cid} isn't in Kubo's export"))?;
            let key = cid.to_string();
            if cid.codec() == 0x55 {
                if data.get(offset..offset + block.len()) != Some(&block[..]) {
                    return Err(format!("raw leaf {cid} isn't the content at {offset}").into());
                }
                leaves.push(json!({ "cid": key, "from": offset, "length": block.len() }));
                offset += block.len();
                continue;
            }
            let node = car::dag_pb(&block).ok_or_else(|| format!("{cid} isn't dag-pb"))?;
            if node.links.is_empty() {
                let (s, e) = node.unixfs_data.unwrap_or((block.len(), block.len()));
                if data.get(offset..offset + (e - s)) != Some(&block[s..e]) {
                    return Err(format!("leaf {cid} isn't the content at {offset}").into());
                }
                leaves.push(json!({
                    "cid": key,
                    "from": offset,
                    "length": e - s,
                    "prefix": B64.encode(&block[..s]),
                    "suffix": B64.encode(&block[e..]),
                }));
                offset += e - s;
                continue;
            }
            if let Some((s, e)) = node.unixfs_data {
                offset += e - s;
            }
            nodes.push(Value::String(key.clone()));
            self.recorded.insert(key, block.clone());
            for (child, _) in node.links.iter().rev() {
                stack.push(*child);
            }
        }
        if offset != data.len() {
            return Err(format!(
                "{root}: the DAG's leaves cover {offset} of {} bytes",
                data.len()
            )
            .into());
        }
        Ok((leaves, nodes))
    }

    fn import(&mut self, kubo: &Kubo, cid: &str) -> Result<Cid, Err> {
        let car = car::read(&kubo.export(cid)?).ok_or("Kubo's export isn't a CAR")?;
        for (c, b) in car.blocks {
            self.all.insert(c, b);
        }
        Ok(Cid::try_from(cid)?)
    }

    async fn files(
        &mut self,
        kubo: &Kubo,
        dir: &Path,
    ) -> Result<Vec<(String, Cid, String, usize)>, Err> {
        let mut out = Vec::new();
        for size in FILE_SIZES {
            let seed = format!("ipfs-file-{size}");
            let data = content::bytes(&seed, size);
            let path = dir.join(format!("{seed}.bin"));
            std::fs::write(&path, &data)?;
            for (v, flags) in [("v0", V0), ("v1", V1)] {
                for layout in ["balanced", "trickle"] {
                    let mut f: Vec<&str> = flags.to_vec();
                    if layout == "trickle" {
                        f.push("--trickle");
                    }
                    let cid_s = kubo.add(&path, &f)?;
                    let cid = self.import(kubo, &cid_s)?;
                    let id = format!("file-{size}-{v}-{layout}");
                    let (leaves, nodes) = self.describe_dag(&cid, &data)?;
                    self.files.push(json!({
                        "id": id,
                        "seed": seed,
                        "size": size,
                        "add": f,
                        "root": cid_s,
                        "nodes": nodes,
                        "leaves": leaves,
                    }));
                    out.push((id, cid, seed.clone(), size));
                }
            }
        }
        Ok(out)
    }

    /// A directory tree on disk, added with `ipfs add -r`; returns the root
    /// and each file's (path, seed, size).
    fn write_tree(base: &Path, files: &[(&str, &str, usize)]) -> Result<(), Err> {
        for (path, seed, size) in files {
            let p = base.join(path);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let data = Self::file_bytes(seed, *size);
            std::fs::write(p, data)?;
        }
        Ok(())
    }

    fn file_bytes(seed: &str, size: usize) -> Vec<u8> {
        if let Some(lit) = seed.strip_prefix("literal:") {
            lit.as_bytes().to_vec()
        } else {
            content::bytes(seed, size)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn directory(
        &mut self,
        kubo: &Kubo,
        dir: &Path,
        id: &str,
        flags: &[&str],
        files: &[(&str, &str, usize)],
        note: &str,
    ) -> Result<(String, Vec<TreeFile>), Err> {
        let base = dir.join(id);
        Self::write_tree(&base, files)?;
        let mut f = vec!["-r"];
        f.extend_from_slice(flags);
        let root = kubo.add(&base, &f)?;
        self.import(kubo, &root)?;
        // Every block of the tree, then each file's leaves out of it.
        let all_blocks: Vec<Cid> = {
            let car = car::read(&kubo.export(&root)?).ok_or("export")?;
            car.blocks.into_iter().map(|(c, _)| c).collect()
        };
        let mut entries = Vec::new();
        let mut leaf_cids = HashSet::new();
        let mut out = Vec::new();
        for (path, seed, size) in files {
            let data = Self::file_bytes(seed, *size);
            let cid_s = String::from_utf8_lossy(&kubo.run(&[
                "resolve",
                "--recursive",
                &format!("/ipfs/{root}/{path}"),
            ])?)
            .trim()
            .trim_start_matches("/ipfs/")
            .to_string();
            let cid = Cid::try_from(cid_s.as_str())?;
            let (leaves, nodes) = self.describe_dag(&cid, &data)?;
            for l in &leaves {
                if let Some(c) = l["cid"].as_str() {
                    leaf_cids.insert(c.to_string());
                }
            }
            let mut e = Map::new();
            e.insert("path".into(), json!(path));
            if let Some(lit) = seed.strip_prefix("literal:") {
                e.insert("text".into(), json!(lit));
            } else {
                e.insert("seed".into(), json!(seed));
            }
            e.insert("size".into(), json!(data.len()));
            e.insert("cid".into(), json!(cid_s));
            e.insert("nodes".into(), Value::Array(nodes));
            e.insert("leaves".into(), Value::Array(leaves));
            entries.push(Value::Object(e));
            out.push(((*path).to_string(), (*seed).to_string(), data.len()));
        }
        let mut nodes = Vec::new();
        for c in all_blocks {
            let key = c.to_string();
            if leaf_cids.contains(&key) {
                continue;
            }
            if let Some(b) = self.all.get(&c) {
                self.recorded.insert(key.clone(), b.clone());
                nodes.push(Value::String(key));
            }
        }
        self.directories.push(json!({
            "id": id,
            "root": root,
            "add": f,
            "note": note,
            "blocks": nodes,
            "entries": entries,
        }));
        Ok((root, out))
    }

    fn content_of(&mut self, e: &Expect) -> &[u8] {
        self.contents
            .entry(format!("{}\u{0}{}", e.seed, e.size))
            .or_insert_with(|| Self::file_bytes(&e.seed, e.size))
    }

    fn describe_body(&mut self, body: &[u8], expect: Option<&Expect>) -> Value {
        if body.is_empty() {
            return json!({ "length": 0 });
        }
        if let Some(e) = expect {
            let from = e.from;
            let seed = e.seed.clone();
            let data = self.content_of(e);
            if data.get(from..from + body.len()) == Some(body) {
                return json!({ "content": { "seed": seed, "from": from, "length": body.len() } });
            }
        }
        if body.len() <= INLINE_BODY_MAX {
            return json!({ "base64": B64.encode(body) });
        }
        json!({ "length": body.len(), "sha256": hex::encode(Sha256::digest(body)) })
    }

    /// One request to `GatewayCore`, as freedom-ipfsd makes it.
    #[allow(clippy::too_many_arguments)]
    async fn native_req(
        &mut self,
        core: &GatewayCore,
        case: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        expect: Option<Expect>,
        note: &str,
    ) -> Result<Vec<(String, String)>, Err> {
        let parsed = freedom_ipfs_gateway::parse_native_request(NativeRequest {
            method: Some(method.to_string()),
            path: path.to_string(),
            headers: Some(
                headers
                    .iter()
                    .map(|(k, v)| NativeRequestHeader {
                        name: k.clone(),
                        value: v.clone(),
                    })
                    .collect(),
            ),
            request_id: Some(1),
            parent_request_id: None,
            top_level_path: Some(path.to_string()),
        });
        let (status, resp_headers, body) = match parsed {
            Ok(p) => {
                let resp = core.handle(p.request).await;
                let status = resp.status().as_u16();
                let h: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.to_string(),
                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                        )
                    })
                    .collect();
                let body = resp
                    .into_body()
                    .collect()
                    .await
                    .map_err(|e| format!("{path}: {e}"))?
                    .to_bytes()
                    .to_vec();
                (status, h, body)
            }
            Err(e) => {
                let n = self.native.len() + 1;
                self.native.push(json!({
                    "id": format!("{case}#{n}"),
                    "case": case,
                    "request": { "method": method, "path": path, "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>() },
                    "parse_error": e.to_string(),
                }));
                return Ok(Vec::new());
            }
        };
        let body_v = self.describe_body(&body, expect.as_ref());
        let n = self.native.iter().filter(|e| e["case"] == case).count() + 1;
        let mut ex = Map::new();
        ex.insert("id".into(), json!(format!("{case}#{n}")));
        ex.insert("case".into(), json!(case));
        if !note.is_empty() {
            ex.insert("note".into(), json!(note));
        }
        ex.insert(
            "request".into(),
            json!({ "method": method, "path": path, "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>() }),
        );
        ex.insert(
            "response".into(),
            json!({
                "status": status,
                "headers": resp_headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                "body": body_v,
            }),
        );
        self.native.push(Value::Object(ex));
        Ok(resp_headers)
    }

    async fn kubo_req(
        &mut self,
        kubo: &Kubo,
        case: &str,
        path: &str,
        headers: Vec<(String, String)>,
        note: &str,
    ) -> Result<(), Err> {
        let (status, h, body) = kubo.get("GET", path, &headers).await?;
        let ctype = h
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let body_v = if ctype.starts_with("application/vnd.ipld.car") {
            match car::read(&body) {
                Some(c) => {
                    // The wire bytes must be the header, the sections as a
                    // CAR writes them, and the trailing bytes: what a replay
                    // rebuilds from this record and the blocks.
                    let mut rebuilt = c.header.clone();
                    for (cid, block) in &c.blocks {
                        rebuilt.extend_from_slice(&car::section(cid, block));
                    }
                    rebuilt.extend_from_slice(&c.trailing);
                    if rebuilt != body {
                        return Err(format!("{case}: Kubo's CAR isn't framed canonically").into());
                    }
                    json!({
                        "car": {
                            "header": B64.encode(&c.header),
                            "blocks": c.blocks.iter().map(|(cid, _)| cid.to_string()).collect::<Vec<_>>(),
                            "trailing": B64.encode(&c.trailing),
                            "complete": c.complete,
                        },
                        "length": body.len(),
                        "sha256": hex::encode(Sha256::digest(&body)),
                    })
                }
                None => {
                    json!({ "length": body.len(), "sha256": hex::encode(Sha256::digest(&body)), "car": null })
                }
            }
        } else if ctype.starts_with(RAW_ACCEPT)
            && let Some(cid) = path
                .strip_prefix("/ipfs/")
                .and_then(|p| p.split(['/', '?']).next())
                .and_then(|c| Cid::try_from(c).ok())
            && (self.all.get(&cid).is_some_and(|b| b[..] == body[..])
                || (cid.hash().code() == 0x00 && cid.hash().digest() == &body[..]))
        {
            // The block the request named, as the node sent it.
            json!({ "block": cid.to_string(), "length": body.len() })
        } else {
            self.describe_body(&body, None)
        };
        let n = self.kubo.iter().filter(|e| e["case"] == case).count() + 1;
        let mut ex = Map::new();
        ex.insert("id".into(), json!(format!("{case}#{n}")));
        ex.insert("case".into(), json!(case));
        if !note.is_empty() {
            ex.insert("note".into(), json!(note));
        }
        ex.insert(
            "request".into(),
            json!({ "method": "GET", "path": path, "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>() }),
        );
        ex.insert(
            "response".into(),
            json!({
                "status": status,
                "headers": h.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                "body": body_v,
            }),
        );
        self.kubo.push(Value::Object(ex));
        Ok(())
    }

    /// `GatewayCore`'s answers for a file: the whole, HEAD, ranges at the
    /// block boundaries, and `If-None-Match` with and without a range.
    async fn native_file(
        &mut self,
        core: &GatewayCore,
        case: &str,
        cid: &str,
        seed: &str,
        size: usize,
    ) -> Result<(), Err> {
        let ex = |from| {
            Some(Expect {
                seed: seed.to_string(),
                size,
                from,
            })
        };
        let path = format!("/ipfs/{cid}");
        let got = self
            .native_req(core, case, "GET", &path, Vec::new(), ex(0), "")
            .await?;
        let etag = got
            .iter()
            .find(|(k, _)| k == "etag")
            .map(|(_, v)| v.clone());
        self.native_req(core, case, "HEAD", &path, Vec::new(), None, "")
            .await?;
        self.native_req(
            core,
            case,
            "GET",
            &path,
            hdrs(&[("accept", NAV_ACCEPT)]),
            ex(0),
            "a navigation's Accept",
        )
        .await?;
        let mut ranges: Vec<(String, Option<usize>)> = Vec::new();
        if size == 0 {
            ranges.push(("bytes=0-".into(), None));
            ranges.push(("bytes=-1".into(), None));
        } else {
            let last = size - 1;
            ranges.push(("bytes=0-".into(), Some(0)));
            ranges.push(("bytes=0-0".into(), Some(0)));
            ranges.push((format!("bytes={last}-"), Some(last)));
            ranges.push(("bytes=-1".into(), Some(last)));
            ranges.push((format!("bytes=-{}", size + 1), Some(0)));
            ranges.push((format!("bytes={size}-"), None));
            ranges.push(("bytes=0-0,2-3".into(), None));
            ranges.push(("bytes=abc".into(), None));
            if size > CHUNK {
                ranges.push((format!("bytes={}-{}", CHUNK - 1, CHUNK), Some(CHUNK - 1)));
                ranges.push((format!("bytes={CHUNK}-"), Some(CHUNK)));
            }
            if size > 4 * CHUNK {
                ranges.push(("bytes=5000000-6000000".into(), Some(5_000_000)));
            }
        }
        for (r, from) in ranges {
            self.native_req(
                core,
                case,
                "GET",
                &path,
                hdrs(&[("range", &r)]),
                from.and_then(ex),
                "",
            )
            .await?;
        }
        if let Some(tag) = etag {
            self.native_req(
                core,
                case,
                "GET",
                &path,
                hdrs(&[("if-none-match", &tag)]),
                ex(0),
                "",
            )
            .await?;
            self.native_req(
                core,
                case,
                "GET",
                &path,
                hdrs(&[("if-none-match", &format!("W/{tag}"))]),
                ex(0),
                "a weak tag",
            )
            .await?;
            self.native_req(
                core,
                case,
                "GET",
                &path,
                hdrs(&[("if-none-match", "\"other\"")]),
                ex(0),
                "",
            )
            .await?;
            if size > 0 {
                self.native_req(
                    core,
                    case,
                    "GET",
                    &path,
                    hdrs(&[("if-none-match", &tag), ("range", "bytes=0-0")]),
                    ex(0),
                    "a range: no 304",
                )
                .await?;
            }
        }
        self.native_req(
            core,
            case,
            "GET",
            &path,
            hdrs(&[("if-none-match", "*")]),
            ex(0),
            "",
        )
        .await?;
        Ok(())
    }

    async fn kubo_file(
        &mut self,
        kubo: &Kubo,
        case: &str,
        cid: &str,
        size: usize,
    ) -> Result<(), Err> {
        let car = hdrs(&[("accept", CAR_ACCEPT)]);
        let p = format!("/ipfs/{cid}?format=car&dag-scope=entity");
        self.kubo_req(kubo, case, &p, car.clone(), "").await?;
        let mut eb = vec!["0:0".to_string(), "0:*".to_string(), "-1:*".to_string()];
        if size > CHUNK {
            eb.push(format!("{}:{}", CHUNK - 1, CHUNK));
            eb.push(format!("{CHUNK}:*"));
        }
        if size > 4 * CHUNK {
            eb.push("5000000:6000000".into());
        }
        eb.push(format!("{}:*", size + 10));
        for e in eb {
            self.kubo_req(
                kubo,
                case,
                &format!("{p}&entity-bytes={e}"),
                car.clone(),
                "",
            )
            .await?;
        }
        self.kubo_req(
            kubo,
            case,
            &p,
            hdrs(&[(
                "accept",
                "application/vnd.ipld.car; version=1; order=dfs; dups=n",
            )]),
            "dups=n",
        )
        .await?;
        self.kubo_req(
            kubo,
            case,
            &p,
            hdrs(&[("accept", "application/vnd.ipld.car")]),
            "no CAR parameters",
        )
        .await?;
        self.kubo_req(
            kubo,
            case,
            &format!("/ipfs/{cid}?format=raw"),
            hdrs(&[("accept", RAW_ACCEPT)]),
            "the root block",
        )
        .await?;
        Ok(())
    }
}

/// Builds the IPFS section.
pub async fn build() -> Result<Value, Err> {
    let mut kubo = Kubo::new()?;
    let dir = work_dir()?;
    let mut s = Ipfs::default();

    let files = s.files(&kubo, &dir).await?;

    // A file whose leaves repeat: Kubo's CAR answers differ by `dups`.
    let unit = content::bytes("ipfs-repeat", CHUNK);
    let repeated: Vec<u8> = unit.iter().copied().cycle().take(4 * CHUNK).collect();
    let rp = dir.join("ipfs-repeat.bin");
    std::fs::write(&rp, &repeated)?;
    let repeat_cid = kubo.add(&rp, &V1)?;
    let rc = s.import(&kubo, &repeat_cid)?;
    let repeat_root = s.all.get(&rc).cloned().ok_or("repeat root")?;
    s.recorded.insert(repeat_cid.clone(), repeat_root);
    s.files.push(json!({
        "id": "file-repeat-v1",
        "content": { "seed": "ipfs-repeat", "unit": CHUNK, "count": 4 },
        "size": 4 * CHUNK,
        "add": V1,
        "root": repeat_cid,
        "nodes": [repeat_cid],
        "leaves": [{ "cid": Cid::new_v1(0x55, multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(&unit))?).to_string(), "from": 0, "length": CHUNK, "repeated": 4 }],
    }));

    // Directories.
    let site: [(&str, &str, usize); 10] = [
        (
            "index.html",
            "literal:<!doctype html><title>site</title><p>index</p>\n",
            0,
        ),
        ("style.css", "ipfs-site-style", 3000),
        ("docs/page.html", "ipfs-site-docs-page", 1200),
        ("docs/sub/x.txt", "ipfs-site-docs-x", 10),
        ("img/photo.jpg", "ipfs-site-photo", 300_000),
        ("ünï/çødé.txt", "ipfs-site-unicode", 7),
        ("日本/ファイル.txt", "ipfs-site-cjk", 8),
        (
            "page",
            "literal:<!DOCTYPE html><p>no extension, sniffed</p>\n",
            0,
        ),
        (
            "  spaced",
            "literal:\u{feff}  <html><p>a byte-order mark and spaces first</p>\n",
            0,
        ),
        ("data", "ipfs-site-data", 600),
    ];
    let (site_v0, _) = s.directory(
        &kubo,
        &dir,
        "site-v0",
        &V0,
        &site,
        "an index.html, nested paths, Unicode names, files without an extension",
    )?;
    let (site_v1, _) = s.directory(
        &kubo,
        &dir,
        "site-v1",
        &V1,
        &site,
        "the same tree as CIDv1 with raw leaves",
    )?;
    let listing: [(&str, &str, usize); 5] = [
        ("a&b<c>.txt", "ipfs-list-1", 11),
        ("b.txt", "ipfs-list-2", 22),
        ("sub/c.txt", "ipfs-list-3", 33),
        ("Zeta.md", "ipfs-list-4", 44),
        ("ü.txt", "ipfs-list-5", 55),
    ];
    let (list_root, _) = s.directory(
        &kubo,
        &dir,
        "listing-v1",
        &V1,
        &listing,
        "no index.html: GatewayCore's listing",
    )?;
    kubo.run(&["config", "Import.UnixFSHAMTDirectorySizeThreshold", "1KiB"])?;
    let names: Vec<String> = (0..60).map(|i| format!("entry-{i:03}.txt")).collect();
    let hamt_files: Vec<(&str, &str, usize)> = names
        .iter()
        .map(|n| (n.as_str(), "ipfs-hamt-entry", 9usize))
        .collect();
    let (hamt_root, _) = s.directory(
        &kubo,
        &dir,
        "hamt-v1",
        &V1,
        &hamt_files,
        "60 entries, sharded (HAMT) at Kubo's threshold lowered to 1KiB",
    )?;
    kubo.run(&[
        "config",
        "Import.UnixFSHAMTDirectorySizeThreshold",
        "256KiB",
    ])?;

    // Identity CIDs.
    let small = dir.join("identity.txt");
    std::fs::write(&small, b"hello")?;
    let ident = kubo.add(
        &small,
        &["--cid-version=1", "--inline", "--inline-limit=32"],
    )?;
    s.identity.push(json!({ "cid": "bafkqaaa", "data": "" }));
    s.identity.push(json!({ "cid": ident, "add": ["--cid-version=1", "--inline", "--inline-limit=32"], "note": "a file of 5 bytes, inlined" }));

    // IPNS.
    let ed_a = Key::ed25519("ipns-ed25519-a");
    let ed_b = Key::ed25519("ipns-ed25519-b");
    let ed_c = Key::ed25519("ipns-ed25519-c");
    let rsa_2048 = Key::rsa("ipns-rsa-2048", 2048, 65537)?;
    let rsa_4096 = Key::rsa("ipns-rsa-4096", 4096, 65537)?;
    let rsa_2048_e3 = Key::rsa("ipns-rsa-2048-e3", 2048, 3)?;
    let rsa_2048_emax = Key::rsa("ipns-rsa-2048-emax", 2048, (1u64 << 33) - 1)?;
    let rsa_8192_emax = Key::rsa("ipns-rsa-8192-emax", 8192, (1u64 << 33) - 1)?;
    let rsa_2041 = Key::rsa("ipns-rsa-2041", 2041, 65537)?;
    let site_value = format!("/ipfs/{site_v1}");
    let file_value = format!(
        "/ipfs/{}",
        files
            .iter()
            .find(|f| f.0 == "file-262145-v1-balanced")
            .map(|f| f.1.to_string())
            .unwrap_or_default()
    );
    let mut cases: Vec<(String, &Key, String, Spec, String)> = Vec::new();
    let a = ed_a.name()?;
    let b = ed_b.name()?;
    let c = ed_c.name()?;
    cases.push((
        "ed25519-v2".into(),
        &ed_a,
        a.clone(),
        Spec::v2(&site_value, 3),
        "V2-only".into(),
    ));
    let mut legacy = Spec::v2(&site_value, 4);
    legacy.legacy = true;
    cases.push((
        "ed25519-legacy".into(),
        &ed_a,
        a.clone(),
        legacy,
        "the legacy V1 fields, equal to the signed ones".into(),
    ));
    let mut unknown = Spec::v2(&site_value, 5);
    unknown.unknown = true;
    cases.push((
        "ed25519-unknown".into(),
        &ed_a,
        a.clone(),
        unknown,
        "unknown entry fields and an unknown signed key".into(),
    ));
    let mut expired = Spec::v2(&site_value, 6);
    expired.validity = ipns::EXPIRED_EOL.to_string();
    cases.push((
        "ed25519-expired".into(),
        &ed_a,
        a.clone(),
        expired,
        "expired".into(),
    ));
    cases.push((
        "ed25519-other-key".into(),
        &ed_b,
        a.clone(),
        Spec::v2(&site_value, 7),
        "signed by another key, under name a".into(),
    ));
    let mut other_pk = Spec::v2(&site_value, 8);
    other_pk.pub_key = true;
    cases.push((
        "ed25519-other-pubkey".into(),
        &ed_b,
        a.clone(),
        other_pk,
        "signed by another key that the record carries in pubKey".into(),
    ));
    let mut no_v2 = Spec::v2(&site_value, 9);
    no_v2.signature_v2 = false;
    no_v2.legacy = true;
    cases.push((
        "ed25519-no-v2".into(),
        &ed_a,
        a.clone(),
        no_v2,
        "without signatureV2, the V1 fields only".into(),
    ));
    let mut legacy_diff = Spec::v2(&site_value, 10);
    legacy_diff.legacy = true;
    legacy_diff.legacy_value = Some(file_value.clone());
    cases.push((
        "ed25519-legacy-differs".into(),
        &ed_a,
        a.clone(),
        legacy_diff,
        "a legacy value that differs from the signed one".into(),
    ));
    cases.push((
        "ed25519-to-rsa".into(),
        &ed_b,
        b.clone(),
        Spec::v2(&format!("/ipns/{}", rsa_2048.name()?), 1),
        "names an RSA-keyed name".into(),
    ));
    cases.push((
        "ed25519-to-dnslink".into(),
        &ed_c,
        c.clone(),
        Spec::v2("/ipns/example.com", 1),
        "names a DNSLink name".into(),
    ));
    for (id, k) in [
        ("rsa-2048", &rsa_2048),
        ("rsa-4096", &rsa_4096),
        ("rsa-2048-e3", &rsa_2048_e3),
        ("rsa-2048-emax", &rsa_2048_emax),
        ("rsa-8192-emax", &rsa_8192_emax),
        ("rsa-2041", &rsa_2041),
    ] {
        let value = if id == "rsa-4096" {
            format!("/ipns/{}", rsa_2048.name()?)
        } else {
            file_value.clone()
        };
        let note = match id {
            "rsa-4096" => "names another RSA-keyed name",
            "rsa-2041" => "a 2,041-bit modulus, which ring takes (deviation rsa-keys)",
            _ => "",
        };
        cases.push((id.into(), k, k.name()?, Spec::v2(&value, 1), note.into()));
    }
    let mut rows = Vec::new();
    // Each name resolves to its valid record with the highest sequence.
    let mut best: HashMap<String, u64> = HashMap::new();
    for (id, key, name, spec, note) in &cases {
        let bytes = ipns::record(spec, key)?;
        let verdict = ipns::native_verdict(name, &bytes);
        if let Some(ok) = verdict.get("ok")
            && let (Some(v), Some(seq)) = (ok["value"].as_str(), ok["sequence"].as_u64())
            && best.get(name).is_none_or(|&b| seq > b)
        {
            best.insert(name.clone(), seq);
            s.names.insert(name.clone(), v.to_string());
        }
        rows.push(json!({
            "id": id,
            "name": name,
            "signer": key.label,
            "note": note,
            "record": B64.encode(&bytes),
            "native": verdict,
        }));
    }
    // Encodings libp2p's deterministic rule forbids, which the native
    // reader re-encodes and takes (deviation rsa-keys).
    // The protobuf's first two bytes are its Type field (0x08 0x00), the
    // rest its Data field.
    let mut noncanon = Vec::new();
    let mut swapped = rsa_2048.proto[2..].to_vec();
    swapped.extend_from_slice(&rsa_2048.proto[..2]);
    noncanon.push(("rsa-fields-reordered", swapped));
    let mut extra = rsa_2048.proto.clone();
    extra.extend_from_slice(&[0x18, 0x01]);
    noncanon.push(("rsa-unknown-key-field", extra));
    // The SubjectPublicKeyInfo's outer length in a longer form than DER's
    // shortest: 0x83 0x00 0x01 0x22 for 0x82 0x01 0x22.
    if rsa_2048.spki.get(..2) == Some(&[0x30, 0x82]) {
        let mut der = vec![0x30, 0x83, 0x00];
        der.extend_from_slice(&rsa_2048.spki[2..]);
        let mut proto = Vec::new();
        ipns::pb_varint(1, 0, &mut proto);
        ipns::pb_bytes(2, &der, &mut proto);
        noncanon.push(("rsa-long-form-der-length", proto));
    }
    for (id, proto) in noncanon {
        let mut spec = Spec::v2(&file_value, 1);
        spec.pub_key = true;
        // The record carries this encoding, signed by the key it encodes.
        let bytes = record_with_pubkey(&spec, &rsa_2048, &proto)?;
        let name = rsa_2048.name()?;
        let verdict = ipns::native_verdict(&name, &bytes);
        rows.push(json!({
            "id": id,
            "name": name,
            "signer": rsa_2048.label,
            "note": "pubKey encoded otherwise than libp2p's deterministic form; the name is the canonical encoding's (deviation rsa-keys)",
            "pub_key": B64.encode(&proto),
            "record": B64.encode(&bytes),
            "native": verdict,
        }));
    }
    s.records = rows;
    let keys: Vec<Value> = [
        &ed_a,
        &ed_b,
        &ed_c,
        &rsa_2048,
        &rsa_4096,
        &rsa_2048_e3,
        &rsa_2048_emax,
        &rsa_8192_emax,
        &rsa_2041,
    ]
    .iter()
    .map(|k| {
        let mut d = k.describe();
        d["name"] = json!(k.name().unwrap_or_default());
        d
    })
    .collect();

    // GatewayCore over every block, and the names the valid records name.
    let provider = Arc::new(MemProvider(s.all.clone()));
    let core = GatewayCore::with_provider_and_name_resolver_config(
        provider,
        Arc::new(Names(s.names.clone())),
        GatewayConfig::new(8).with_request_queue_timeout(std::time::Duration::from_millis(15_000)),
    );
    for (id, cid, seed, size) in &files {
        s.native_file(&core, id, &cid.to_string(), seed, *size)
            .await?;
    }
    let rc = repeat_cid.clone();
    s.native_req(
        &core,
        "file-repeat-v1",
        "GET",
        &format!("/ipfs/{rc}"),
        Vec::new(),
        None,
        "",
    )
    .await?;
    for (case, root, tree) in [
        ("site-v0", &site_v0, &site[..]),
        ("site-v1", &site_v1, &site[..]),
    ] {
        let find = |p: &str| {
            tree.iter().find(|f| f.0 == p).map(|f| Expect {
                seed: f.1.to_string(),
                size: if f.1.starts_with("literal:") {
                    f.1.len() - 8
                } else {
                    f.2
                },
                from: 0,
            })
        };
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/"),
            Vec::new(),
            find("index.html"),
            "the index document",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}"),
            Vec::new(),
            find("index.html"),
            "no trailing slash",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "HEAD",
            &format!("/ipfs/{root}/"),
            Vec::new(),
            None,
            "",
        )
        .await?;
        for (p, ..) in tree {
            s.native_req(
                &core,
                case,
                "GET",
                &format!("/ipfs/{root}/{}", percent(p)),
                Vec::new(),
                find(p),
                "",
            )
            .await?;
            s.native_req(
                &core,
                case,
                "HEAD",
                &format!("/ipfs/{root}/{}", percent(p)),
                Vec::new(),
                None,
                "",
            )
            .await?;
        }
        // freedom-ipfsd hands the plan's path to the native-request parser
        // as it is, percent-encoded as an HTTP client sends it; the same
        // names unencoded show what GatewayCore resolves.
        for p in ["ünï/çødé.txt", "日本/ファイル.txt", "  spaced"] {
            s.native_req(
                &core,
                case,
                "GET",
                &format!("/ipfs/{root}/{p}"),
                Vec::new(),
                find(p),
                "the path unencoded",
            )
            .await?;
        }
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/docs"),
            Vec::new(),
            None,
            "a directory without index.html",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/docs/"),
            Vec::new(),
            None,
            "",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/missing"),
            Vec::new(),
            None,
            "a missing name",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/docs/missing"),
            Vec::new(),
            None,
            "",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/docs/../index.html"),
            Vec::new(),
            None,
            "a .. segment",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/docs/%2E%2E/index.html"),
            Vec::new(),
            None,
            "an encoded .. segment",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/index.html/x"),
            Vec::new(),
            None,
            "a path below a file",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/img/photo.jpg"),
            hdrs(&[("range", "bytes=262143-262144")]),
            find("img/photo.jpg").map(|e| Expect { from: 262_143, ..e }),
            "",
        )
        .await?;
        s.native_req(
            &core,
            case,
            "GET",
            &format!("/ipfs/{root}/page"),
            hdrs(&[("range", "bytes=1-")]),
            find("page").map(|e| Expect { from: 1, ..e }),
            "a range not from 0: no sniffing",
        )
        .await?;
    }
    for (p, ..) in &listing {
        let ep = percent(p);
        s.native_req(
            &core,
            "listing-v1",
            "GET",
            &format!("/ipfs/{list_root}/{ep}"),
            Vec::new(),
            None,
            "",
        )
        .await?;
    }
    s.native_req(
        &core,
        "listing-v1",
        "GET",
        &format!("/ipfs/{list_root}/"),
        Vec::new(),
        None,
        "the listing",
    )
    .await?;
    s.native_req(
        &core,
        "listing-v1",
        "HEAD",
        &format!("/ipfs/{list_root}/"),
        Vec::new(),
        None,
        "",
    )
    .await?;
    s.native_req(
        &core,
        "listing-v1",
        "GET",
        &format!("/ipfs/{list_root}/"),
        hdrs(&[("range", "bytes=0-10")]),
        None,
        "a range on a listing",
    )
    .await?;
    s.native_req(
        &core,
        "listing-v1",
        "GET",
        &format!("/ipfs/{list_root}/"),
        hdrs(&[("if-none-match", "*")]),
        None,
        "",
    )
    .await?;
    s.native_req(
        &core,
        "listing-v1",
        "GET",
        &format!("/ipfs/{list_root}/sub/"),
        Vec::new(),
        None,
        "a sub-directory's listing",
    )
    .await?;
    for n in [
        "entry-000.txt",
        "entry-031.txt",
        "entry-059.txt",
        "entry-060.txt",
    ] {
        s.native_req(
            &core,
            "hamt-v1",
            "GET",
            &format!("/ipfs/{hamt_root}/{n}"),
            Vec::new(),
            None,
            "",
        )
        .await?;
    }
    s.native_req(
        &core,
        "hamt-v1",
        "GET",
        &format!("/ipfs/{hamt_root}/"),
        Vec::new(),
        None,
        "a sharded directory's listing",
    )
    .await?;
    s.native_req(
        &core,
        "identity",
        "GET",
        "/ipfs/bafkqaaa",
        Vec::new(),
        None,
        "the empty identity CID",
    )
    .await?;
    s.native_req(
        &core,
        "identity",
        "GET",
        &format!("/ipfs/{ident}"),
        Vec::new(),
        None,
        "",
    )
    .await?;
    let mut named: Vec<(String, String)> = keys
        .iter()
        .filter_map(|k| {
            Some((
                k["label"].as_str()?.to_string(),
                k["name"].as_str()?.to_string(),
            ))
        })
        .filter(|(_, n)| s.names.contains_key(n))
        .collect();
    named.sort();
    for (label, name) in &named {
        let case = format!("ipns-{label}");
        s.native_req(
            &core,
            &case,
            "GET",
            &format!("/ipns/{name}/"),
            Vec::new(),
            None,
            "",
        )
        .await?;
        s.native_req(
            &core,
            &case,
            "HEAD",
            &format!("/ipns/{name}/"),
            Vec::new(),
            None,
            "",
        )
        .await?;
        s.native_req(
            &core,
            &case,
            "GET",
            &format!("/ipns/{name}"),
            Vec::new(),
            None,
            "no trailing slash",
        )
        .await?;
        s.native_req(
            &core,
            &case,
            "GET",
            &format!("/ipns/{name}/docs/page.html"),
            Vec::new(),
            None,
            "",
        )
        .await?;
    }

    // Kubo's trustless answers.
    kubo.start_daemon().await?;
    for (id, cid, _, size) in &files {
        s.kubo_file(&kubo, id, &cid.to_string(), *size).await?;
    }
    let car = hdrs(&[("accept", CAR_ACCEPT)]);
    let raw = hdrs(&[("accept", RAW_ACCEPT)]);
    for dups in ["y", "n"] {
        s.kubo_req(
            &kubo,
            "file-repeat-v1",
            &format!("/ipfs/{rc}?format=car&dag-scope=entity"),
            hdrs(&[(
                "accept",
                &format!("application/vnd.ipld.car; version=1; order=dfs; dups={dups}"),
            )]),
            "repeated leaves",
        )
        .await?;
    }
    for (case, root) in [
        ("site-v0", &site_v0),
        ("site-v1", &site_v1),
        ("listing-v1", &list_root),
        ("hamt-v1", &hamt_root),
    ] {
        s.kubo_req(
            &kubo,
            case,
            &format!("/ipfs/{root}?format=car&dag-scope=entity"),
            car.clone(),
            "the directory as an entity",
        )
        .await?;
        s.kubo_req(
            &kubo,
            case,
            &format!("/ipfs/{root}?format=raw"),
            raw.clone(),
            "",
        )
        .await?;
        s.kubo_req(
            &kubo,
            case,
            &format!("/ipfs/{root}/missing?format=car&dag-scope=entity"),
            car.clone(),
            "a missing name",
        )
        .await?;
    }
    for (case, root) in [("site-v0", &site_v0), ("site-v1", &site_v1)] {
        for p in [
            "index.html",
            "docs/page.html",
            "img/photo.jpg",
            "ünï/çødé.txt",
        ] {
            s.kubo_req(
                &kubo,
                case,
                &format!("/ipfs/{root}/{}?format=car&dag-scope=entity", percent(p)),
                car.clone(),
                "the path, then the entity",
            )
            .await?;
        }
        s.kubo_req(
            &kubo,
            case,
            &format!(
                "/ipfs/{root}/img/photo.jpg?format=car&dag-scope=entity&entity-bytes=262144:*"
            ),
            car.clone(),
            "",
        )
        .await?;
        s.kubo_req(
            &kubo,
            case,
            &format!("/ipfs/{root}/docs/../index.html?format=car&dag-scope=entity"),
            car.clone(),
            "a .. segment",
        )
        .await?;
    }
    s.kubo_req(
        &kubo,
        "hamt-v1",
        &format!("/ipfs/{hamt_root}/entry-031.txt?format=car&dag-scope=entity"),
        car.clone(),
        "a name through the shards",
    )
    .await?;
    s.kubo_req(
        &kubo,
        "identity",
        "/ipfs/bafkqaaa?format=raw",
        raw.clone(),
        "",
    )
    .await?;
    s.kubo_req(
        &kubo,
        "identity",
        "/ipfs/bafkqaaa?format=car&dag-scope=entity",
        car.clone(),
        "",
    )
    .await?;
    s.kubo_req(
        &kubo,
        "identity",
        &format!("/ipfs/{ident}?format=car&dag-scope=entity"),
        car.clone(),
        "",
    )
    .await?;
    let absent = Cid::new_v1(
        0x55,
        multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(b"absent"))?,
    )
    .to_string();
    s.kubo_req(
        &kubo,
        "absent",
        &format!("/ipfs/{absent}?format=raw"),
        raw.clone(),
        "a block the node doesn't hold",
    )
    .await?;
    s.kubo_req(
        &kubo,
        "absent",
        &format!("/ipfs/{absent}?format=car&dag-scope=entity"),
        car.clone(),
        "",
    )
    .await?;
    let first_leaf = files
        .iter()
        .find(|f| f.0 == "file-10485760-v1-balanced")
        .map(|f| f.1.to_string())
        .unwrap_or_default();
    s.kubo_req(
        &kubo,
        "file-10485760-v1-balanced",
        &format!("/ipfs/{first_leaf}?format=raw"),
        hdrs(&[("accept", RAW_ACCEPT), ("range", "bytes=0-9")]),
        "a Range on a raw block, which the verifier never sends",
    )
    .await?;
    if let Some((label, name)) = named.first() {
        s.kubo_req(
            &kubo,
            &format!("ipns-{label}"),
            &format!("/ipns/{name}?format=ipns-record"),
            hdrs(&[("accept", RECORD_ACCEPT)]),
            "an offline Kubo holds no record: the generator doesn't publish",
        )
        .await?;
    }
    drop(kubo);
    let _ = std::fs::remove_dir_all(&dir);

    let blocks: Map<String, Value> = s
        .recorded
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(B64.encode(v))))
        .collect();
    let section = json!({
        "files": s.files,
        "directories": s.directories,
        "identity": s.identity,
        "ipns": { "keys": keys, "records": s.records },
        "blocks": blocks,
        "native": s.native,
        "kubo": s.kubo,
    });
    // Every recorded CAR, rebuilt from the section alone, as a replay does.
    crate::replay::rebuild_kubo_cars(&section)?;
    Ok(section)
}

/// A record whose `pubKey` is `proto`, signed by `key`.
fn record_with_pubkey(spec: &Spec, key: &Key, proto: &[u8]) -> Result<Vec<u8>, Err> {
    // The record as written for `key`, then its pubKey field swapped.
    let canonical = ipns::record(spec, key)?;
    let mut needle = vec![0x3a];
    let mut len = key.proto.len();
    while len >= 0x80 {
        needle.push((len as u8) | 0x80);
        len >>= 7;
    }
    needle.push(len as u8);
    needle.extend_from_slice(&key.proto);
    let at = canonical
        .windows(needle.len())
        .position(|w| w == &needle[..])
        .ok_or("pubKey field")?;
    let mut field = vec![0x3a];
    let mut len = proto.len();
    while len >= 0x80 {
        field.push((len as u8) | 0x80);
        len >>= 7;
    }
    field.push(len as u8);
    field.extend_from_slice(proto);
    let mut out = canonical[..at].to_vec();
    out.extend_from_slice(&field);
    out.extend_from_slice(&canonical[at + needle.len()..]);
    Ok(out)
}
