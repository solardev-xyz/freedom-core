//! Mantaray manifests as Ant v0.5.71 reads them (design 0009, Manifests and
//! feeds): a node's bytes, de-obfuscated and parsed, and the path lookup,
//! as a machine that asks for each node it needs and is handed its bytes.
//! `vectors/dweb-verify.json`'s manifests (each lookup's `lookup_path`
//! answer, from Ant) are the contract.
//!
//! A node is a Swarm file: the caller joins its chunk tree and checks every
//! chunk before handing the bytes over (at most [`MAX_NODE`], which it has
//! reserved). Parsing copies the node once, to de-obfuscate it, and keeps
//! at most 256 forks (one per bitmap bit) and the metadata keys the walk
//! reads.

use fc_evm::keccak256;

/// The core's cap on one node (deviation `manifest-node-cap`; Ant's is 32 MiB).
pub const MAX_NODE: usize = 1 << 20;
const KEY: usize = 32;
const VERSION: usize = 31;
const HEADER: usize = KEY + VERSION + 1;
const FORK_PRE_REF: usize = 32;
const PREFIX_MAX: usize = 30;
const WITH_METADATA: u8 = 16;

pub const CONTENT_TYPE: &str = "Content-Type";
pub const FILENAME: &str = "Filename";
pub const INDEX_DOCUMENT: &str = "website-index-document";
pub const ERROR_DOCUMENT: &str = "website-error-document";
pub const FEED_OWNER: &str = "swarm-feed-owner";
pub const FEED_TOPIC: &str = "swarm-feed-topic";
pub const FEED_TYPE: &str = "swarm-feed-type";

/// Why a node can't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    /// No mantaray version hash: the bytes are a file, which Ant serves
    /// as the reference's bytes.
    NotAManifest,
    /// A version hash, then something Ant refuses: too short, a reference
    /// size other than 0, 32 or 64, a prefix length outside 1 to 30, or
    /// metadata that isn't a flat JSON object of strings.
    Malformed,
    /// Past [`MAX_NODE`].
    TooLarge,
}

fn version_hash(v: &[u8]) -> [u8; VERSION] {
    let h = keccak256(v);
    let mut out = [0u8; VERSION];
    out.copy_from_slice(&h[..VERSION]);
    out
}

/// One fork: the byte its bitmap bit names, its prefix, the child's
/// reference, and the metadata keys the walk reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fork {
    pub byte: u8,
    pub node_type: u8,
    pub prefix: Vec<u8>,
    pub child: Vec<u8>,
    pub metadata: Metadata,
}

/// The metadata keys the walk reads, last value winning as in Ant's map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata(pub Vec<(String, String)>);

impl Metadata {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn set(&mut self, key: String, value: String) {
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.0.push((key, value));
        }
    }

    /// Ant's merge of a fork's metadata onto its child: a key the child
    /// already has keeps its value.
    fn merge_under(&mut self, parent: &Metadata) {
        for (k, v) in &parent.0 {
            if self.get(k).is_none() {
                self.0.push((k.clone(), v.clone()));
            }
        }
    }
}

const KEPT: [&str; 7] = [
    CONTENT_TYPE,
    FILENAME,
    INDEX_DOCUMENT,
    ERROR_DOCUMENT,
    FEED_OWNER,
    FEED_TOPIC,
    FEED_TYPE,
];

/// A parsed node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The node's entry, `ref_size` bytes; all zeros when it has none.
    pub entry: Vec<u8>,
    /// Ascending by byte.
    pub forks: Vec<Fork>,
    /// What the walk merged onto this node from the fork that named it.
    pub metadata: Metadata,
}

impl Node {
    fn fork(&self, byte: u8) -> Option<&Fork> {
        self.forks.iter().find(|f| f.byte == byte)
    }
}

/// Whether a node's first bytes carry a mantaray version hash (Ant's header
/// sniff on a node's leftmost leaf).
pub fn has_manifest_header(data: &[u8]) -> bool {
    if data.len() < HEADER {
        return false;
    }
    let mut v = [0u8; VERSION];
    for (i, b) in v.iter_mut().enumerate() {
        *b = data[KEY + i] ^ data[i % KEY];
    }
    v == version_hash(b"mantaray:0.2") || v == version_hash(b"mantaray:0.1")
}

/// Parses a node's joined bytes (Ant `Node::unmarshal`).
pub fn parse_node(input: &[u8]) -> Result<Node, NodeError> {
    if input.len() > MAX_NODE {
        return Err(NodeError::TooLarge);
    }
    if input.len() < HEADER {
        return Err(NodeError::Malformed);
    }
    let mut data = input.to_vec();
    let mut key = [0u8; KEY];
    key.copy_from_slice(&data[..KEY]);
    for (i, b) in data[KEY..].iter_mut().enumerate() {
        *b ^= key[i % KEY];
    }
    let v = &data[KEY..KEY + VERSION];
    let v02 = version_hash(b"mantaray:0.2");
    let v01 = version_hash(b"mantaray:0.1");
    if v != v02 && v != v01 {
        return Err(NodeError::NotAManifest);
    }
    let is_v01 = v == v01;
    let ref_size = usize::from(data[KEY + VERSION]);
    if ref_size != 0 && ref_size != 32 && ref_size != 64 {
        return Err(NodeError::Malformed);
    }
    let mut at = HEADER;
    let entry = data
        .get(at..at + ref_size)
        .ok_or(NodeError::Malformed)?
        .to_vec();
    at += ref_size;
    let index: [u8; 32] = data
        .get(at..at + 32)
        .ok_or(NodeError::Malformed)?
        .try_into()
        .map_err(|_| NodeError::Malformed)?;
    at += 32;
    let mut forks = Vec::new();
    for byte in 0..=255u8 {
        if (index[usize::from(byte / 8)] >> (byte % 8)) & 1 == 0 {
            continue;
        }
        let node_type = *data.get(at).ok_or(NodeError::Malformed)?;
        let mut size = FORK_PRE_REF + ref_size;
        let mut meta = None;
        if !is_v01 && node_type & WITH_METADATA != 0 {
            let len = data
                .get(at + size..at + size + 2)
                .ok_or(NodeError::Malformed)?;
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            meta = Some((at + size + 2, len));
            size += 2 + len;
        }
        if data.len() < at + size {
            return Err(NodeError::Malformed);
        }
        let prefix_len = usize::from(data[at + 1]);
        if prefix_len == 0 || prefix_len > PREFIX_MAX {
            return Err(NodeError::Malformed);
        }
        let prefix = data[at + 2..at + 2 + prefix_len].to_vec();
        let child = data[at + FORK_PRE_REF..at + FORK_PRE_REF + ref_size].to_vec();
        let metadata = match meta {
            Some((start, len)) if len > 0 => parse_metadata(&data[start..start + len])?,
            _ => Metadata::default(),
        };
        forks.push(Fork {
            byte,
            node_type,
            prefix,
            child,
            metadata,
        });
        at += size;
    }
    Ok(Node {
        entry,
        forks,
        metadata: Metadata::default(),
    })
}

/// Ant's `parse_metadata`: UTF-8, trailing newlines (Bee's padding)
/// trimmed, then a flat JSON object of strings.
fn parse_metadata(raw: &[u8]) -> Result<Metadata, NodeError> {
    let s = std::str::from_utf8(raw).map_err(|_| NodeError::Malformed)?;
    let s = s.trim_end_matches('\n');
    if s.is_empty() {
        return Ok(Metadata::default());
    }
    let b = s.as_bytes();
    let mut i = 0;
    let ws = |b: &[u8], i: &mut usize| {
        while *i < b.len() && b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    };
    ws(b, &mut i);
    if i >= b.len() || b[i] != b'{' {
        return Err(NodeError::Malformed);
    }
    i += 1;
    let mut out = Metadata::default();
    loop {
        ws(b, &mut i);
        if i < b.len() && b[i] == b'}' {
            return Ok(out);
        }
        let key = json_string(s, &mut i)?;
        ws(b, &mut i);
        if i >= b.len() || b[i] != b':' {
            return Err(NodeError::Malformed);
        }
        i += 1;
        ws(b, &mut i);
        let value = json_string(s, &mut i)?;
        if KEPT.contains(&key.as_str()) {
            out.set(key, value);
        }
        ws(b, &mut i);
        if i < b.len() && b[i] == b',' {
            i += 1;
            continue;
        }
        if i < b.len() && b[i] == b'}' {
            return Ok(out);
        }
        return Err(NodeError::Malformed);
    }
}

/// Ant's `parse_json_string`: the escapes it reads, `\uXXXX` as one BMP
/// code point (dropped when it isn't one), raw UTF-8 passed through.
fn json_string(s: &str, i: &mut usize) -> Result<String, NodeError> {
    let b = s.as_bytes();
    if *i >= b.len() || b[*i] != b'"' {
        return Err(NodeError::Malformed);
    }
    *i += 1;
    let mut out = String::new();
    while *i < b.len() {
        match b[*i] {
            b'"' => {
                *i += 1;
                return Ok(out);
            }
            b'\\' => {
                *i += 1;
                let c = *b.get(*i).ok_or(NodeError::Malformed)?;
                match c {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'u' => {
                        if *i + 4 >= b.len() {
                            return Err(NodeError::Malformed);
                        }
                        let hex = s.get(*i + 1..*i + 5).ok_or(NodeError::Malformed)?;
                        let cp = u32::from_str_radix(hex, 16).map_err(|_| NodeError::Malformed)?;
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                        }
                        *i += 4;
                    }
                    _ => return Err(NodeError::Malformed),
                }
                *i += 1;
            }
            _ => {
                let ch = s[*i..].chars().next().ok_or(NodeError::Malformed)?;
                out.push(ch);
                *i += ch.len_utf8();
            }
        }
    }
    Err(NodeError::Malformed)
}

/// What a lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The entry: its data reference and metadata.
    Found {
        data_ref: Vec<u8>,
        metadata: Metadata,
    },
    /// No entry: Ant's 404 (`root` for an empty path without an index
    /// document, whose message differs).
    NotFound { root: bool },
    /// `path/` begins an entry: Ant's 308 to it.
    Directory,
}

/// What the lookup needs next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The node at this reference, joined and checked: [`Lookup::node`].
    Need(Vec<u8>),
    Done(Outcome),
    /// Ant's lookup fails with an error, not a miss: a node on the walk's
    /// path that isn't a manifest or can't be parsed, or an entry whose
    /// reference size isn't 32 or 64.
    Failed(NodeError),
}

#[derive(Debug, Clone)]
enum Phase {
    /// Walking `path` for an entry; on a miss, `then` follows.
    Walk {
        path: Vec<u8>,
        at: usize,
        then: Box<Phase>,
    },
    /// Whether `path` (the request's plus `/`) begins an entry.
    Prefix {
        path: Vec<u8>,
        at: usize,
        then: Box<Phase>,
    },
    Done(Outcome),
}

/// Ant's `lookup_path` on a manifest whose root node the caller holds.
/// Feeds are the caller's: a root whose `/` fork names a feed is resolved
/// first, and this machine starts at the feed's root.
#[derive(Debug, Clone)]
pub struct Lookup {
    root: Node,
    node: Node,
    phase: Phase,
}

fn walk(path: &str, then: Phase) -> Phase {
    Phase::Walk {
        path: path.as_bytes().to_vec(),
        at: 0,
        then: Box::new(then),
    }
}

impl Lookup {
    pub fn new(root: Node, path: &str) -> (Self, Step) {
        let path = path.trim_start_matches('/');
        let slash = root
            .fork(b'/')
            .map(|f| f.metadata.clone())
            .unwrap_or_default();
        let index = slash.get(INDEX_DOCUMENT).map(str::to_owned);
        let error = slash.get(ERROR_DOCUMENT).map(str::to_owned);
        let not_found = |root| Phase::Done(Outcome::NotFound { root });
        let phase = if path.is_empty() {
            match &index {
                Some(idx) => walk(idx, not_found(true)),
                None => not_found(true),
            }
        } else {
            // The literal path; then the directory redirect; then the path
            // joined with the index document; then the error document.
            let mut tail = not_found(false);
            if let Some(err) = &error
                && path != err
            {
                tail = walk(err, tail);
            }
            if let Some(idx) = &index
                && !path.ends_with(idx.as_str())
            {
                let base = path.trim_end_matches('/');
                let joined = if base.is_empty() {
                    idx.clone()
                } else {
                    format!("{base}/{idx}")
                };
                tail = walk(&joined, tail);
            }
            let prefix = Phase::Prefix {
                path: format!("{path}/").into_bytes(),
                at: 0,
                then: Box::new(tail),
            };
            walk(path, prefix)
        };
        let mut l = Self {
            node: root.clone(),
            root,
            phase,
        };
        let step = l.run();
        (l, step)
    }

    /// Hands over the node the last [`Step::Need`] asked for. Its metadata
    /// is merged from the fork that named it, as Ant merges it. A node that
    /// can't be read fails a walk, but only ends a directory-prefix check,
    /// which Ant answers "no" and moves on.
    pub fn node(&mut self, bytes: &[u8]) -> Step {
        let mut child = match parse_node(bytes) {
            Ok(n) => n,
            Err(e) => {
                if let Phase::Prefix { then, .. } = std::mem::replace(
                    &mut self.phase,
                    Phase::Done(Outcome::NotFound { root: false }),
                ) {
                    self.restart(*then);
                    return self.run();
                }
                return Step::Failed(e);
            }
        };
        let fork_meta = match &self.phase {
            Phase::Walk { path, at, .. } | Phase::Prefix { path, at, .. } => self
                .node
                .fork(path[*at])
                .map(|f| f.metadata.clone())
                .unwrap_or_default(),
            Phase::Done(_) => Metadata::default(),
        };
        if let Phase::Walk { .. } = self.phase {
            child.metadata.merge_under(&fork_meta);
        }
        // Advance past the fork just followed.
        match &mut self.phase {
            Phase::Walk { path, at, .. } | Phase::Prefix { path, at, .. } => {
                let len = self.node.fork(path[*at]).map_or(0, |f| f.prefix.len());
                *at += len;
            }
            Phase::Done(_) => {}
        }
        self.node = child;
        self.run()
    }

    fn run(&mut self) -> Step {
        loop {
            match std::mem::replace(
                &mut self.phase,
                Phase::Done(Outcome::NotFound { root: false }),
            ) {
                Phase::Done(o) => {
                    self.phase = Phase::Done(o.clone());
                    return Step::Done(o);
                }
                Phase::Walk { path, at, then } => {
                    if at == path.len() {
                        let e = &self.node.entry;
                        if e.len() != 32 && e.len() != 64 {
                            return Step::Failed(NodeError::Malformed);
                        }
                        if e.iter().any(|&b| b != 0) {
                            let o = Outcome::Found {
                                data_ref: e.clone(),
                                metadata: self.node.metadata.clone(),
                            };
                            self.phase = Phase::Done(o.clone());
                            return Step::Done(o);
                        }
                        // A zero entry: Bee's "no value here".
                        self.restart(*then);
                        continue;
                    }
                    let Some(fork) = self.node.fork(path[at]) else {
                        self.restart(*then);
                        continue;
                    };
                    let rest = &path[at..];
                    if rest.len() < fork.prefix.len()
                        || rest[..fork.prefix.len()] != fork.prefix[..]
                    {
                        self.restart(*then);
                        continue;
                    }
                    let need = fork.child.clone();
                    self.phase = Phase::Walk { path, at, then };
                    return Step::Need(need);
                }
                Phase::Prefix { path, at, then } => {
                    if at == path.len() {
                        self.phase = Phase::Done(Outcome::Directory);
                        return Step::Done(Outcome::Directory);
                    }
                    let Some(fork) = self.node.fork(path[at]) else {
                        self.restart(*then);
                        continue;
                    };
                    let rest = &path[at..];
                    let common = fork
                        .prefix
                        .iter()
                        .zip(rest)
                        .take_while(|(a, b)| a == b)
                        .count();
                    if common < fork.prefix.len() {
                        if common == rest.len() {
                            self.phase = Phase::Done(Outcome::Directory);
                            return Step::Done(Outcome::Directory);
                        }
                        self.restart(*then);
                        continue;
                    }
                    if common == rest.len() {
                        self.phase = Phase::Done(Outcome::Directory);
                        return Step::Done(Outcome::Directory);
                    }
                    let need = fork.child.clone();
                    self.phase = Phase::Prefix { path, at, then };
                    return Step::Need(need);
                }
            }
        }
    }

    /// The next phase starts again from the root.
    fn restart(&mut self, next: Phase) {
        self.node = self.root.clone();
        self.phase = next;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// A v0.2 node as Bee writes it, unobfuscated: forks of
    /// `(byte, prefix, child, metadata JSON)`.
    fn node(entry: &[u8], forks: &[(&[u8], &[u8], Option<&str>)]) -> Vec<u8> {
        let mut p = vec![0u8; KEY];
        p.extend_from_slice(&version_hash(b"mantaray:0.2"));
        let ref_size = forks.first().map_or(entry.len(), |f| f.1.len());
        p.push(ref_size as u8);
        p.extend_from_slice(entry);
        let mut bitmap = [0u8; 32];
        for (prefix, _, _) in forks {
            bitmap[usize::from(prefix[0] / 8)] |= 1 << (prefix[0] % 8);
        }
        p.extend_from_slice(&bitmap);
        for (prefix, child, meta) in forks {
            p.push(if meta.is_some() { 2 | WITH_METADATA } else { 2 });
            p.push(prefix.len() as u8);
            p.extend_from_slice(prefix);
            p.resize(p.len() + PREFIX_MAX - prefix.len(), 0);
            p.extend_from_slice(child);
            if let Some(m) = meta {
                let mut padded = m.as_bytes().to_vec();
                while (padded.len() + 2) % 32 != 0 {
                    padded.push(b'\n');
                }
                p.extend_from_slice(&(padded.len() as u16).to_be_bytes());
                p.extend_from_slice(&padded);
            }
        }
        p
    }

    #[test]
    fn metadata_as_ant_reads_it() {
        // Built at run time: a backslash-u escape, as Bee writes non-ASCII.
        let text = format!(
            r#"{{"Content-Type":"text\/html","Filename":"a{}u00e9.txt","Other":"x"}}"#,
            '\\'
        );
        let m = parse_metadata(text.as_bytes()).unwrap();
        assert_eq!(m.get(CONTENT_TYPE), Some("text/html"));
        assert_eq!(m.get(FILENAME), Some("a\u{e9}.txt"));
        assert_eq!(m.get("Other"), None);
        // Bee's newline padding, and the last of a repeated key.
        let m = parse_metadata(b"{\"Filename\":\"a\",\"Filename\":\"b\"}\n\n\n").unwrap();
        assert_eq!(m.get(FILENAME), Some("b"));
        assert_eq!(parse_metadata(b"\n\n").unwrap(), Metadata::default());
        for bad in [
            &br#"{"Filename":{"a":"b"}}"#[..],
            br#"{"Filename":1}"#,
            br#"["a"]"#,
            br#"{"a":"\q"}"#,
            b"{\"a\":\"b\"",
        ] {
            assert_eq!(
                parse_metadata(bad),
                Err(NodeError::Malformed),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn what_ant_refuses() {
        let good = node(&[0; 32], &[(b"a", &[1; 32], None)]);
        assert!(parse_node(&good).is_ok());
        assert_eq!(parse_node(&good[..HEADER - 1]), Err(NodeError::Malformed));
        let mut raw = good.clone();
        raw[KEY] ^= 1;
        assert_eq!(parse_node(&raw), Err(NodeError::NotAManifest));
        assert!(!has_manifest_header(&raw) && has_manifest_header(&good));
        let mut size = good.clone();
        size[KEY + VERSION] = 16;
        assert_eq!(parse_node(&size), Err(NodeError::Malformed));
        let at = HEADER + 32 + 32;
        for len in [0u8, 31] {
            let mut p = good.clone();
            p[at + 1] = len;
            assert_eq!(
                parse_node(&p),
                Err(NodeError::Malformed),
                "prefix length {len}"
            );
        }
        assert_eq!(
            parse_node(&good[..good.len() - 1]),
            Err(NodeError::Malformed)
        );
        assert_eq!(parse_node(&vec![0; MAX_NODE + 1]), Err(NodeError::TooLarge));
    }

    #[test]
    fn an_obfuscated_node_reads_the_same() {
        let plain = node(
            &[0; 32],
            &[(b"abc", &[7; 32], Some(r#"{"Filename":"abc"}"#))],
        );
        let mut obf = plain.clone();
        let key = [0x5a_u8; 32];
        obf[..KEY].copy_from_slice(&key);
        for (i, b) in obf[KEY..].iter_mut().enumerate() {
            *b ^= key[i % KEY];
        }
        assert_eq!(parse_node(&obf), parse_node(&plain));
    }

    /// The walk into a child that isn't a manifest fails; the directory
    /// check that meets one moves on.
    #[test]
    fn unreadable_children() {
        let root = parse_node(&node(&[0; 32], &[(b"dir/x", &[2; 32], None)])).unwrap();
        let (mut l, step) = Lookup::new(root.clone(), "dir/x");
        assert_eq!(step, Step::Need(vec![2; 32]));
        assert_eq!(l.node(&[0x41; 100]), Step::Failed(NodeError::NotAManifest));
        // "dir" misses literally, then the prefix check walks "dir/":
        // the fork's prefix "dir/x" begins with it, so it is a directory
        // without loading anything.
        let (_, step) = Lookup::new(root, "dir");
        assert_eq!(step, Step::Done(Outcome::Directory));
    }

    #[test]
    fn an_entry_of_another_size_fails() {
        // A ref-size-0 node reached at the path's end.
        let child = node(&[], &[]);
        let root = parse_node(&node(&[0; 32], &[(b"a", &[3; 32], None)])).unwrap();
        let (mut l, step) = Lookup::new(root, "a");
        assert_eq!(step, Step::Need(vec![3; 32]));
        assert_eq!(l.node(&child), Step::Failed(NodeError::Malformed));
    }
}
