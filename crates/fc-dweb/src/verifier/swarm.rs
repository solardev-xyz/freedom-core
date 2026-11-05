//! The Swarm walk (design 0009, The Swarm walk; Leaves), in Ant's
//! resolution order (`ar/mantaray.rs` `lookup_path_inner`, `ag/node.rs`
//! `run_stream_bzz`):
//!
//! 1. **The root,** `/chunks/<root>`, and Ant's header sniff down its
//!    leftmost chunks: a root that isn't a manifest is served as the
//!    reference's bytes. A manifest node is joined from its chunks (at most
//!    1 MiB, deviation `manifest-node-cap`).
//! 2. **A feed root:** `/feeds` for the index, which is the node's word,
//!    then the update's single-owner chunk, checked against the feed's
//!    owner and that index. Its target becomes the manifest's root, and the
//!    label `latest_asserted`; a target that isn't a manifest gives Ant's
//!    fallback to the URL's own bytes (freedom-hq/ant#235).
//! 3. **The path,** through `fc_swarm::manifest::Lookup`: Ant's 404s and
//!    308 come from verified nodes.
//! 4. **The file:** its root chunk, then the head; then its intermediate
//!    chunks, at most two level-1 chunks ahead and four chunk requests at
//!    once, and one `/bytes` stream for the leaves the range needs, each
//!    checked before its bytes go out, with `/chunks` as the fallback.
//!
//! Every chunk is a content-addressed one at its reference, except the feed
//! update: a single-owner chunk anywhere else is unverifiable (deviation
//! `soc-references`), and so is an encrypted reference (`encrypted-in-walk`).

use std::collections::{BTreeMap, VecDeque};

use fc_swarm::CHUNK_SIZE;
use fc_swarm::manifest::{self, Lookup, Metadata, NodeError, Outcome, Step};
use fc_swarm::tree;
use fc_swarm::verify::{Chunk, FeedUpdate, MAX_CHUNK_WIRE, Refusal, SPAN_SIZE};

use super::ant::{self, Entry, Feed, NotFound, Ranges};
use super::charged::Charged;
use super::jobs::{Verdict, Work};
use super::{Ask, Failure, MAX_CHUNK_PIECES, PieceFailure, PieceId};

/// The machine's bookkeeping, with the Swarm walk's tags. The walk holds
/// its memory only as [`Charged`] values, whose charges only `charged.rs`
/// sets, from what it measures, and doesn't import the raw hold and release
/// ([`super::Holding`]): a charge can't go while what it covers is live.
type Core = super::Core<Tag>;
/// Bytes the walk holds, under their charge.
type Bytes = Charged<Vec<u8>>;
/// Chunks a sniff checked, by address, which the join or the body reuses.
type Known = Vec<([u8; 32], Bytes)>;
use crate::bzz::SWARM_HEADERS;
use crate::plan::ContentTrust;
use crate::validate::Refusal as PlanRefusal;

/// A single-owner chunk on the wire: identifier, signature, then a chunk.
const SOC_MAX: usize = 32 + 65 + MAX_CHUNK_WIRE;
/// Levels of intermediate chunks a file may have (Bee's cap; 0009, Bounds).
const MAX_LEVELS: u8 = 8;
/// Ant's `HEADER_SNIFF_MAX_DEPTH`.
const SNIFF_DEPTH: usize = 8;
/// Ant's `NODE_HEADER_SIZE`: key, version hash and reference size.
const NODE_HEADER: usize = 64;
/// A parsed child reference's cost: its address and length.
const CHILD_COST: usize = 40;
/// A head's headers beside the entry's strings: their names, the fixed
/// values, the ETag, the lengths and the vector that holds them.
const HEAD_ROOM: usize = 1024;

/// What a piece or a job is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tag {
    /// The root chunk of the node being loaded.
    NodeRoot,
    /// The next leftmost chunk of the header sniff.
    Sniff,
    /// A node's leaf, joined at this offset.
    JoinLeaf(u64),
    /// An intermediate chunk at this offset and depth.
    Inter(u64, u8),
    Feed,
    Update,
    FileRoot,
    Bytes,
    /// A leaf's own chunk, when its streamed bytes didn't match.
    Fallback(u64),
    /// A leaf's streamed bytes.
    Leaf(u64),
}

fn refusal(r: Refusal) -> Failure {
    match r {
        Refusal::VerificationFailed => Failure::VerificationFailed,
        Refusal::Unverifiable => Failure::Unverifiable,
    }
}

fn chunk_view(wire: &[u8]) -> Option<Chunk<'_>> {
    let span: [u8; SPAN_SIZE] = wire.get(..SPAN_SIZE)?.try_into().ok()?;
    Some(Chunk {
        span,
        payload: &wire[SPAN_SIZE..],
    })
}

/// A chunk's span, its level byte taken off as Bee decodes it.
fn span_of(wire: &[u8]) -> u64 {
    chunk_view(wire).map_or(0, |c| tree::decode_span(&c.span).1)
}

/// A verified chunk the walk reads as structure goes back for the
/// partition's cache (0009, The structure cache): an intermediate chunk,
/// and, where `node` (a manifest node's own chunk), a leaf that starts with
/// a manifest's header. Data leaves and single-owner chunks never do.
fn remember(core: &mut Core, address: &[u8; 32], wire: &[u8], node: bool) {
    let payload = wire.get(SPAN_SIZE..).unwrap_or(&[]);
    let structure = if span_of(wire) > CHUNK_SIZE as u64 {
        true
    } else {
        node && payload.len() >= NODE_HEADER && manifest::has_manifest_header(payload)
    };
    if structure {
        core.remember(*address, wire);
    }
}

fn chunk_headers() -> Vec<(String, String)> {
    SWARM_HEADERS
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// `%XX` decoded once, as Ant's router decodes its path; an escape that
/// isn't one stays as it is.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (
                b.get(i + 1).and_then(|c| char::from(*c).to_digit(16)),
                b.get(i + 2).and_then(|c| char::from(*c).to_digit(16)),
            )
        {
            out.push(u8::try_from(h * 16 + l).unwrap_or(0));
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Asks for a chunk as a whole piece.
fn fetch_chunk(core: &mut Core, tag: Tag, address: &[u8; 32]) -> Option<PieceId> {
    core.fetch(
        tag,
        format!("/chunks/{}", ant::hex(address)),
        chunk_headers(),
        Ask::Whole(SOC_MAX),
    )
}

/// A whole piece's answer: 200, or its status as the failure.
fn ok_status(status: u16) -> Result<(), Failure> {
    if status == 200 {
        Ok(())
    } else {
        Err(Failure::Status(status))
    }
}

/// Each of `known`'s chunks goes, then its charge.
fn release_known(core: &mut Core, known: Known) {
    for (_, wire) in known {
        wire.release(core);
    }
}

fn chunk_address(work: &Work) -> Option<[u8; 32]> {
    match work {
        Work::Chunk { address, .. } => Some(*address),
        _ => None,
    }
}

/// A chunk job's work, back: its address, and its wire under the work's
/// charge. Other work goes, with its charge.
fn chunk_work(core: &mut Core, work: Charged<Work>) -> Option<([u8; 32], Bytes)> {
    let Some(address) = chunk_address(&work) else {
        work.release(core);
        return None;
    };
    let wire = work.try_map(core, |w| match w {
        Work::Chunk { wire, .. } => Some(wire),
        _ => None,
    })?;
    Some((address, wire))
}

/// A leaf job's streamed bytes, back under the work's charge and measured
/// again: a fallback's chunk beside them goes first, then its part of the
/// charge.
fn leaf_work(core: &mut Core, work: Charged<Work>) -> Option<Bytes> {
    let bytes = work.try_map(core, |w| match w {
        Work::Leaf { bytes, .. } => Some(bytes),
        Work::LeafChunk { bytes, wire, .. } => {
            drop(wire);
            Some(bytes)
        }
        _ => None,
    })?;
    Some(bytes.remake(core, |bytes| bytes))
}

// ---------------------------------------------------------------------------
// A file's chunk tree, read in order.

/// A loaded intermediate chunk: its children, the one to visit next, and
/// where that child starts.
#[derive(Debug)]
struct Frame {
    pos: u64,
    children: Vec<([u8; 32], u64)>,
    next: usize,
    depth: u8,
    /// Whether any child is an intermediate chunk: a level-1 chunk's are
    /// all leaves, and it has nothing to fetch.
    inner: bool,
}

impl Frame {
    fn parse(wire: &[u8], pos: u64, len: u64, depth: u8) -> Result<Self, Failure> {
        let chunk = chunk_view(wire).ok_or(Failure::VerificationFailed)?;
        let node = tree::intermediate(&chunk, len).map_err(refusal)?;
        let children: Vec<([u8; 32], u64)> =
            (0..node.len()).filter_map(|i| node.child(i)).collect();
        let inner = children.iter().any(|&(_, l)| !tree::is_leaf(l));
        Ok(Self {
            pos,
            children,
            next: 0,
            depth,
            inner,
        })
    }

    /// The frame under its charge: its children's.
    fn charged(self, core: &mut Core) -> Charged<Self> {
        let cost = self.children.len() * CHILD_COST;
        Charged::new(core, self, cost)
    }

    /// Moves past the next child, of `len` bytes.
    fn skip(&mut self, len: u64) {
        self.next += 1;
        self.pos += len;
    }
}

#[derive(Debug)]
enum Ahead {
    /// Asked for, or being hashed.
    Fetching {
        address: [u8; 32],
        len: u64,
    },
    Ready(Charged<Frame>),
    Failed(Failure),
}

/// An intermediate chunk the tree asks for.
#[derive(Debug, Clone, Copy)]
struct Want {
    start: u64,
    depth: u8,
    address: [u8; 32],
    len: u64,
    /// The cursor waits for it.
    blocking: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    Leaf {
        address: [u8; 32],
        start: u64,
        len: u64,
    },
    /// An intermediate chunk on the way isn't loaded yet.
    Wait,
    Done,
}

/// The leaves covering `[from, to)` in order, as Ant's joiner reads the
/// tree: each child's length from its parent's geometry.
#[derive(Debug)]
struct Tree {
    from: u64,
    to: u64,
    stack: Vec<Charged<Frame>>,
    ahead: BTreeMap<(u64, u8), Ahead>,
    /// How far past the cursor intermediate chunks are fetched.
    lookahead: u64,
}

impl Tree {
    fn new(
        core: &mut Core,
        root: &[u8],
        len: u64,
        from: u64,
        to: u64,
        lookahead: u64,
    ) -> Result<Self, Failure> {
        let frame = Frame::parse(root, 0, len, 0)?.charged(core);
        Ok(Self {
            from,
            to,
            stack: vec![frame],
            ahead: BTreeMap::new(),
            lookahead,
        })
    }

    fn next(&mut self, core: &mut Core) -> Result<Next, Failure> {
        loop {
            let Some(top) = self.stack.last_mut() else {
                return Ok(Next::Done);
            };
            if top.next >= top.children.len() || top.pos >= self.to {
                if let Some(f) = self.stack.pop() {
                    f.release(core);
                }
                continue;
            }
            let (address, len) = top.children[top.next];
            let start = top.pos;
            let depth = top.depth + 1;
            if len == 0 || start + len <= self.from {
                top.get_mut().skip(len);
                continue;
            }
            if tree::is_leaf(len) {
                top.get_mut().skip(len);
                return Ok(Next::Leaf {
                    address,
                    start,
                    len,
                });
            }
            if depth >= MAX_LEVELS {
                return Err(Failure::Unverifiable);
            }
            match self.ahead.remove(&(start, depth)) {
                Some(Ahead::Ready(frame)) => {
                    top.get_mut().skip(len);
                    self.stack.push(frame);
                }
                Some(Ahead::Failed(f)) => return Err(f),
                Some(a) => {
                    self.ahead.insert((start, depth), a);
                    return Ok(Next::Wait);
                }
                None => return Ok(Next::Wait),
            }
        }
    }

    /// Intermediate chunks to fetch, in the order they're read: the one the
    /// cursor waits for (the top chunk's first child the range needs, when
    /// it isn't a leaf), then those ahead within the lookahead. Each with
    /// whether the cursor waits for it.
    fn wants(&self) -> Vec<Want> {
        let mut out = Vec::new();
        let Some(top) = self.stack.last() else {
            return out;
        };
        let horizon = top
            .pos
            .max(self.from)
            .saturating_add(self.lookahead)
            .min(self.to);
        for (level, frame) in self.stack.iter().enumerate().rev() {
            let mut first = level + 1 == self.stack.len();
            if !frame.inner {
                continue;
            }
            let mut pos = frame.pos;
            for &(address, len) in frame.children.iter().skip(frame.next) {
                let start = pos;
                pos += len;
                if len == 0 || start + len <= self.from {
                    continue;
                }
                if start >= self.to {
                    break;
                }
                let blocking = std::mem::replace(&mut first, false);
                if tree::is_leaf(len) {
                    continue;
                }
                if !blocking && start >= horizon {
                    break;
                }
                let depth = frame.depth + 1;
                if !self.ahead.contains_key(&(start, depth)) && depth < MAX_LEVELS {
                    out.push(Want {
                        start,
                        depth,
                        address,
                        len,
                        blocking,
                    });
                }
            }
        }
        out
    }

    /// `a` in place of what the tree had at `key`: a frame it replaces
    /// goes with its charge.
    fn put(&mut self, core: &mut Core, key: (u64, u8), a: Ahead) {
        if let Some(Ahead::Ready(old)) = self.ahead.insert(key, a) {
            old.release(core);
        }
    }

    /// Asks for what [`Tree::wants`], within the chunk requests' bound,
    /// taking chunks already checked from `known` (each used once, then
    /// released); the one the cursor waits for must fit the request's
    /// memory.
    fn fetch(&mut self, core: &mut Core, known: &mut Known) -> Result<(), Failure> {
        for w in self.wants() {
            let (start, depth) = (w.start, w.depth);
            self.put(
                core,
                (start, depth),
                Ahead::Fetching {
                    address: w.address,
                    len: w.len,
                },
            );
            if let Some(i) = known.iter().position(|(a, _)| *a == w.address) {
                let (_, wire) = known.swap_remove(i);
                self.settle(core, start, depth, Ok(&wire));
                wire.release(core);
                continue;
            }
            if core.whole_pieces() >= MAX_CHUNK_PIECES {
                self.ahead.remove(&(start, depth));
                break;
            }
            if fetch_chunk(core, Tag::Inter(start, depth), &w.address).is_none() {
                self.ahead.remove(&(start, depth));
                if w.blocking {
                    return Err(Failure::Memory);
                }
                break;
            }
        }
        Ok(())
    }

    /// Where the cursor is: its depth, and the next child's offset there.
    fn cursor(&self) -> (usize, u64, usize) {
        self.stack
            .last()
            .map_or((0, 0, 0), |t| (self.stack.len(), t.pos, t.next))
    }

    fn address_of(&self, start: u64, depth: u8) -> Option<([u8; 32], u64)> {
        match self.ahead.get(&(start, depth)) {
            Some(Ahead::Fetching { address, len }) => Some((*address, *len)),
            _ => None,
        }
    }

    /// An intermediate chunk's piece answered or its check came back.
    fn settle(&mut self, core: &mut Core, start: u64, depth: u8, result: Result<&[u8], Failure>) {
        let Some((_, len)) = self.address_of(start, depth) else {
            return;
        };
        let entry = match result.and_then(|wire| Frame::parse(wire, start, len, depth)) {
            Ok(frame) => Ahead::Ready(frame.charged(core)),
            Err(f) => Ahead::Failed(f),
        };
        self.put(core, (start, depth), entry);
    }

    /// The tree goes, each frame before its charge.
    fn release(self, core: &mut Core) {
        for f in self.stack {
            f.release(core);
        }
        for (_, a) in self.ahead {
            if let Ahead::Ready(f) = a {
                f.release(core);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Loading a manifest node: its root chunk, the sniff, the join.

/// What a node's load found.
#[derive(Debug)]
enum Loaded {
    /// The node's joined bytes.
    Node(Bytes),
    /// Ant's sniff found its first data chunk without a version hash.
    NotAManifest,
    /// A manifest node past the core's 1 MiB.
    TooLarge,
}

impl Loaded {
    fn release(self, core: &mut Core) {
        if let Loaded::Node(bytes) = self {
            bytes.release(core);
        }
    }
}

#[derive(Debug)]
enum LoadState {
    Root,
    /// Descending the leftmost references: `child` is the chunk asked for.
    Sniff {
        depth: usize,
        child: [u8; 32],
    },
    Join(Join),
}

#[derive(Debug)]
struct Join {
    /// The node's bytes, made at its size within room reserved first.
    buf: Bytes,
    tree: Tree,
    /// Leaves asked for or hashing, by offset: their address and length.
    leaves: BTreeMap<u64, ([u8; 32], u64)>,
    done: bool,
}

/// A node load (Ant's `load_node_ref_with_credit`).
#[derive(Debug)]
struct Load {
    address: [u8; 32],
    state: LoadState,
    /// The node's root chunk, once checked.
    root: Option<Bytes>,
    /// Chunks the sniff checked, which the join reuses.
    known: Known,
}

enum Progress {
    Pending,
    Loaded(Loaded),
    Failed(Failure),
}

impl Load {
    fn start(core: &mut Core, address: [u8; 32]) -> Result<Self, Failure> {
        fetch_chunk(core, Tag::NodeRoot, &address).ok_or(Failure::Memory)?;
        Ok(Self {
            address,
            state: LoadState::Root,
            root: None,
            known: Vec::new(),
        })
    }

    /// A load whose root chunk is in hand and checked: a v2 feed update's.
    fn with_root(core: &mut Core, address: [u8; 32], wire: Bytes) -> (Self, Progress) {
        let mut load = Self {
            address,
            state: LoadState::Root,
            root: None,
            known: Vec::new(),
        };
        let p = load.rooted(core, wire);
        (load, p)
    }

    /// The load goes: each of its buffers and its tree's frames, then
    /// their charges.
    fn release(self, core: &mut Core) {
        if let LoadState::Join(j) = self.state {
            j.buf.release(core);
            j.tree.release(core);
        }
        if let Some(root) = self.root {
            root.release(core);
        }
        release_known(core, self.known);
    }

    /// The root chunk passed: the load keeps it.
    fn rooted(&mut self, core: &mut Core, wire: Bytes) -> Progress {
        if let Some(old) = self.root.replace(wire) {
            old.release(core);
        }
        self.sniff_from(core, None, 0)
    }

    /// Ant's `leftmost_leaf_is_not_a_manifest`, from the chunk in hand: the
    /// root (`at` none) or the sniff's `at`th.
    fn sniff_from(&mut self, core: &mut Core, at: Option<usize>, depth: usize) -> Progress {
        let (mut at, mut depth) = (at, depth);
        loop {
            if depth >= SNIFF_DEPTH {
                return self.join(core);
            }
            let chunk: &[u8] = match at {
                None => self.root.as_deref().map_or(&[], Vec::as_slice),
                Some(i) => self.known.get(i).map_or(&[], |(_, w)| w.as_slice()),
            };
            let payload = &chunk[SPAN_SIZE.min(chunk.len())..];
            if span_of(chunk) <= CHUNK_SIZE as u64 {
                let raw = payload.len() < NODE_HEADER || !manifest::has_manifest_header(payload);
                if raw {
                    return Progress::Loaded(Loaded::NotAManifest);
                }
                return self.join(core);
            }
            let Some(child) = payload.get(..32).and_then(|c| <[u8; 32]>::try_from(c).ok()) else {
                return self.join(core);
            };
            if let Some(i) = self.known.iter().position(|(a, _)| *a == child) {
                at = Some(i);
                depth += 1;
                continue;
            }
            if fetch_chunk(core, Tag::Sniff, &child).is_none() {
                return Progress::Failed(Failure::Memory);
            }
            self.state = LoadState::Sniff { depth, child };
            return Progress::Pending;
        }
    }

    /// The node is a manifest, or may be one: join it, within 1 MiB.
    fn join(&mut self, core: &mut Core) -> Progress {
        let Some(root) = self.root.as_deref() else {
            return Progress::Failed(Failure::Unverifiable);
        };
        let len = span_of(root);
        let Ok(size) = usize::try_from(len) else {
            return Progress::Loaded(Loaded::TooLarge);
        };
        if size > manifest::MAX_NODE {
            return Progress::Loaded(Loaded::TooLarge);
        }
        if tree::is_leaf(len) {
            let Some(bytes) = root.get(SPAN_SIZE..).and_then(|p| p.get(..size)) else {
                return Progress::Failed(Failure::Unverifiable);
            };
            // The node's bytes, copied within room reserved for them.
            return match Charged::make(core, size, || bytes.to_vec()) {
                Some(bytes) => Progress::Loaded(Loaded::Node(bytes)),
                None => Progress::Failed(Failure::Memory),
            };
        }
        let Some(buf) = Charged::make(core, size, || vec![0; size]) else {
            return Progress::Failed(Failure::Memory);
        };
        let tree = match Tree::new(core, root, len, 0, len, u64::MAX) {
            Ok(t) => t,
            Err(f) => {
                buf.release(core);
                return Progress::Failed(f);
            }
        };
        self.state = LoadState::Join(Join {
            buf,
            tree,
            leaves: BTreeMap::new(),
            done: false,
        });
        self.pump(core)
    }

    /// Moves the join on: known chunks first, then pieces within the bound.
    fn pump(&mut self, core: &mut Core) -> Progress {
        loop {
            let LoadState::Join(join) = &mut self.state else {
                return Progress::Pending;
            };
            if let Err(f) = join.tree.fetch(core, &mut self.known) {
                return Progress::Failed(f);
            }
            let mut moved = false;
            while !join.done && core.whole_pieces() < MAX_CHUNK_PIECES {
                match join.tree.next(core) {
                    Err(f) => return Progress::Failed(f),
                    Ok(Next::Done) => join.done = true,
                    Ok(Next::Wait) => break,
                    Ok(Next::Leaf {
                        address,
                        start,
                        len,
                    }) => {
                        moved = true;
                        if let Some((_, w)) = self.known.iter().find(|(a, _)| *a == address) {
                            if let Err(f) = Self::place(join, start, len, w) {
                                return Progress::Failed(f);
                            }
                            continue;
                        }
                        if fetch_chunk(core, Tag::JoinLeaf(start), &address).is_none() {
                            return Progress::Failed(Failure::Memory);
                        }
                        join.leaves.insert(start, (address, len));
                    }
                }
            }
            // The cursor may have moved on to a chunk not yet asked for.
            if let Err(f) = join.tree.fetch(core, &mut self.known) {
                return Progress::Failed(f);
            }
            if join.done && join.leaves.is_empty() {
                let LoadState::Join(join) = std::mem::replace(&mut self.state, LoadState::Root)
                else {
                    return Progress::Pending;
                };
                join.tree.release(core);
                // The buffer goes to the caller with its charge.
                return Progress::Loaded(Loaded::Node(join.buf));
            }
            if !moved {
                return Progress::Pending;
            }
        }
    }

    /// A joined leaf's bytes: the first `len` of its payload.
    fn place(join: &mut Join, start: u64, len: u64, wire: &[u8]) -> Result<(), Failure> {
        let payload = wire.get(SPAN_SIZE..).ok_or(Failure::VerificationFailed)?;
        let (s, n) = (
            usize::try_from(start).map_err(|_| Failure::Unverifiable)?,
            usize::try_from(len).map_err(|_| Failure::Unverifiable)?,
        );
        let bytes = payload.get(..n).ok_or(Failure::Unverifiable)?;
        join.buf
            .bytes_mut()
            .get_mut(s..s + n)
            .ok_or(Failure::Unverifiable)?
            .copy_from_slice(bytes);
        Ok(())
    }

    fn whole(&mut self, core: &mut Core, tag: Tag, status: u16, body: Bytes) -> Progress {
        if let Err(f) = ok_status(status) {
            body.release(core);
            return Progress::Failed(f);
        }
        let address = match (tag, &self.state) {
            (Tag::NodeRoot, LoadState::Root) => Some(self.address),
            (Tag::Sniff, LoadState::Sniff { child, .. }) => Some(*child),
            (Tag::JoinLeaf(start), LoadState::Join(j)) => j.leaves.get(&start).map(|(a, _)| *a),
            (Tag::Inter(start, depth), LoadState::Join(j)) => {
                j.tree.address_of(start, depth).map(|(a, _)| a)
            }
            _ => None,
        };
        match address {
            Some(address) => core.hash_charged(tag, body.map(|wire| Work::Chunk { address, wire })),
            None => body.release(core),
        }
        Progress::Pending
    }

    fn hashed(
        &mut self,
        core: &mut Core,
        tag: Tag,
        verdict: Verdict,
        work: Charged<Work>,
    ) -> Progress {
        let Verdict::Chunk(result) = verdict else {
            work.release(core);
            return Progress::Failed(Failure::Unverifiable);
        };
        let Some((address, wire)) = chunk_work(core, work) else {
            return Progress::Failed(Failure::Unverifiable);
        };
        if let Err(r) = result {
            wire.release(core);
            return Progress::Failed(refusal(r));
        }
        match tag {
            Tag::NodeRoot => {
                remember(core, &address, &wire, true);
                self.rooted(core, wire)
            }
            Tag::Sniff => {
                let LoadState::Sniff { depth, .. } = self.state else {
                    wire.release(core);
                    return Progress::Pending;
                };
                remember(core, &address, &wire, true);
                // Kept for the join, which reads the same chunks.
                self.known.push((address, wire));
                self.state = LoadState::Root;
                self.sniff_from(core, Some(self.known.len() - 1), depth + 1)
            }
            Tag::JoinLeaf(start) => {
                let LoadState::Join(join) = &mut self.state else {
                    wire.release(core);
                    return Progress::Pending;
                };
                // A manifest node's own bytes.
                core.remember(address, &wire);
                let placed = join
                    .leaves
                    .remove(&start)
                    .map(|(_, len)| Self::place(join, start, len, &wire));
                wire.release(core);
                match placed {
                    Some(Ok(())) => self.pump(core),
                    Some(Err(f)) => Progress::Failed(f),
                    None => Progress::Pending,
                }
            }
            Tag::Inter(start, depth) => {
                let LoadState::Join(join) = &mut self.state else {
                    wire.release(core);
                    return Progress::Pending;
                };
                remember(core, &address, &wire, false);
                join.tree.settle(core, start, depth, Ok(&wire));
                wire.release(core);
                self.pump(core)
            }
            _ => {
                wire.release(core);
                Progress::Pending
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The body: the file's leaves through one /bytes stream.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafState {
    Filling,
    Hashing,
    /// Its streamed bytes didn't match: `/chunks` is asked once.
    NeedsFallback,
    Fallback,
    Passed,
    Failed(Failure),
}

#[derive(Debug)]
struct Leaf {
    start: u64,
    address: [u8; 32],
    len: usize,
    /// Its bytes, made at its length when it starts filling; none while a
    /// job has them.
    bytes: Option<Bytes>,
    state: LeafState,
}

#[derive(Debug)]
struct ByteStream {
    id: PieceId,
    /// The file offset of the stream's next byte.
    pos: u64,
    /// The frames as they came, each whole under its charge until all its
    /// bytes are used.
    stash: VecDeque<Bytes>,
    /// How much of the stash's first frame is used.
    front_at: usize,
    /// Of those, the bytes skipped, not given to a leaf: their credit goes
    /// back with the frame.
    front_skipped: usize,
    headed: bool,
    /// Still open: not ended, failed or cancelled.
    open: bool,
}

impl ByteStream {
    /// The first frame, once all its bytes are used, goes, then its
    /// charge; the bytes it skipped are credited back.
    fn used(&mut self, core: &mut Core) {
        if !self.stash.front().is_some_and(|f| self.front_at >= f.len()) {
            return;
        }
        if let Some(frame) = self.stash.pop_front() {
            frame.release(core);
        }
        self.front_at = 0;
        let skipped = std::mem::take(&mut self.front_skipped);
        if skipped > 0 {
            core.consumed(self.id, skipped);
        }
    }
}

#[derive(Debug)]
struct Body {
    reference: [u8; 32],
    tree: Tree,
    /// The body: file bytes `a..=b`.
    a: u64,
    b: u64,
    /// The stream's interval: the needed leaves, `fs..=fe`.
    fs: u64,
    fe: u64,
    total: u64,
    stream: Option<ByteStream>,
    leaves: VecDeque<Leaf>,
    /// The tree has no more leaves to give.
    tree_done: bool,
    /// The tree failed, or the stream's answer can't be used: what isn't
    /// checked by then fails with this, and the stash is dropped.
    stopped: Option<Failure>,
    /// The stream ended, or main ended it, before the needed bytes were in.
    /// What it stashed still fills leaves; once that runs out, the next
    /// leaf fails with this.
    ended: Option<Failure>,
    /// The next file byte to release.
    released: u64,
    /// Intermediate chunks the root's sniff checked, used once.
    known: Known,
}

impl Body {
    fn stream_id(&self) -> Option<PieceId> {
        self.stream.as_ref().map(|s| s.id)
    }

    /// Moves everything on: `Ok(true)` once every byte of the body is out,
    /// and `Err` ends the request.
    fn pump(&mut self, core: &mut Core) -> Result<bool, Failure> {
        // Until nothing moves: a chunk the sniff checked settles at once,
        // and may make the next leaf known with no piece left to wait on.
        loop {
            let before = self.mark();
            self.fetch_tree(core);
            if self.stream.is_none() && self.stopped.is_none() {
                self.open(core)?;
            }
            self.fill(core);
            if self.mark() == before {
                break;
            }
        }
        self.fallbacks(core)?;
        self.deliver(core)
    }

    /// Where the body stands, to tell whether a pass moved it.
    fn mark(&self) -> (bool, u64, usize, (usize, u64, usize), usize, bool) {
        (
            self.stream.is_some(),
            self.stream.as_ref().map_or(0, |s| s.pos),
            self.leaves.len(),
            self.tree.cursor(),
            self.tree.ahead.len(),
            self.stopped.is_some(),
        )
    }

    fn fetch_tree(&mut self, core: &mut Core) {
        if self.stopped.is_none()
            && let Err(f) = self.tree.fetch(core, &mut self.known)
        {
            self.stopped = Some(f);
        }
    }

    /// Opens the stream once the first leaf is known.
    fn open(&mut self, core: &mut Core) -> Result<(), Failure> {
        if self.leaves.is_empty() {
            match self.tree.next(core) {
                Ok(Next::Leaf {
                    address,
                    start,
                    len,
                }) => self.push_leaf(core, address, start, len),
                Ok(Next::Wait) => return Ok(()),
                Ok(Next::Done) => {
                    self.tree_done = true;
                    return Ok(());
                }
                Err(f) => {
                    self.stopped = Some(f);
                    return Ok(());
                }
            }
            if self.stopped.is_some() {
                return Ok(());
            }
        }
        let mut headers = chunk_headers();
        headers.push(("range".to_owned(), format!("bytes={}-{}", self.fs, self.fe)));
        let id = core
            .fetch(
                Tag::Bytes,
                format!("/bytes/{}", ant::hex(&self.reference)),
                headers,
                Ask::Stream(None),
            )
            .ok_or(Failure::Memory)?;
        self.stream = Some(ByteStream {
            id,
            pos: self.fs,
            stash: VecDeque::new(),
            front_at: 0,
            front_skipped: 0,
            headed: false,
            open: true,
        });
        Ok(())
    }

    /// The next leaf, its buffer made at its length within room reserved
    /// first; without the room, the body stops.
    fn push_leaf(&mut self, core: &mut Core, address: [u8; 32], start: u64, len: u64) {
        // A leaf's length is at most a chunk's.
        let len = usize::try_from(len).unwrap_or(CHUNK_SIZE);
        let Some(bytes) = Charged::make(core, len, || Vec::with_capacity(len)) else {
            self.stopped = Some(Failure::Memory);
            return;
        };
        self.leaves.push_back(Leaf {
            start,
            address,
            len,
            bytes: Some(bytes),
            state: LeafState::Filling,
        });
    }

    /// Stops the stream: cancelled, its frames dropped and the bytes no
    /// leaf took credited back.
    fn close_stream(&mut self, core: &mut Core) {
        if let Some(s) = self.stream.as_mut() {
            if s.open {
                s.open = false;
                core.cancel_piece(s.id);
            }
            let used = std::mem::take(&mut s.front_at);
            let mut credit = std::mem::take(&mut s.front_skipped);
            for (i, frame) in s.stash.drain(..).enumerate() {
                credit += frame.len().saturating_sub(if i == 0 { used } else { 0 });
                frame.release(core);
            }
            core.consumed(s.id, credit);
        }
    }

    /// The stash's bytes into their leaves, as the tree names them.
    fn fill(&mut self, core: &mut Core) {
        loop {
            let Some(s) = self.stream.as_mut() else {
                return;
            };
            let Some(front) = s.stash.front() else {
                break;
            };
            let avail = front.len() - s.front_at;
            if s.pos > self.fe || self.stopped.is_some() {
                // Past what is needed, or past a failure: dropped.
                self.close_stream(core);
                return;
            }
            if s.pos < self.fs {
                // A 200's bytes before the first needed leaf: unread.
                let gap = usize::try_from(self.fs - s.pos).unwrap_or(usize::MAX);
                let n = gap.min(avail);
                s.front_at += n;
                s.front_skipped += n;
                s.pos += n as u64;
                s.used(core);
                continue;
            }
            let pos = s.pos;
            let filling = self
                .leaves
                .back()
                .is_some_and(|l| l.state == LeafState::Filling);
            if !filling {
                match self.tree.next(core) {
                    Ok(Next::Leaf {
                        address,
                        start,
                        len,
                    }) => self.push_leaf(core, address, start, len),
                    Ok(Next::Wait) => break,
                    Ok(Next::Done) => {
                        // The leaves end here: the rest isn't used.
                        self.tree_done = true;
                        if let Some(s) = self.stream.as_mut() {
                            s.pos = self.fe + 1;
                        }
                    }
                    Err(f) => self.stopped = Some(f),
                }
                continue;
            }
            let (Some(s), Some(leaf)) = (self.stream.as_mut(), self.leaves.back_mut()) else {
                break;
            };
            let Some(bytes) = leaf.bytes.as_mut() else {
                // A filling leaf holds its buffer.
                self.stopped = Some(Failure::Unverifiable);
                continue;
            };
            if leaf.start + bytes.len() as u64 != pos {
                // The tree's next leaf doesn't start where the stream is.
                self.stopped = Some(Failure::Unverifiable);
                continue;
            }
            let Some(front) = s.stash.front() else {
                break;
            };
            let want = leaf.len - bytes.len();
            let end = s.front_at + want.min(front.len() - s.front_at);
            // Copied into the leaf's own buffer: the frame stays whole, and
            // charged, until all its bytes are used.
            let n = bytes.fill_from(&front[s.front_at..end]);
            let full = bytes.len() == leaf.len;
            s.front_at += n;
            s.pos += n as u64;
            s.used(core);
            if full {
                leaf.state = LeafState::Hashing;
                if let Some(bytes) = leaf.bytes.take() {
                    let (address, len) = (leaf.address, leaf.len);
                    core.hash_charged(
                        Tag::Leaf(leaf.start),
                        bytes.map(|bytes| Work::Leaf {
                            address,
                            len,
                            bytes,
                        }),
                    );
                }
            }
        }
        // Every needed byte is in: the stream isn't needed any more.
        if self.stream.as_ref().is_some_and(|s| s.pos > self.fe) {
            self.close_stream(core);
        }
    }

    fn fallbacks(&mut self, core: &mut Core) -> Result<(), Failure> {
        for leaf in &mut self.leaves {
            if leaf.state != LeafState::NeedsFallback {
                continue;
            }
            if core.whole_pieces() >= MAX_CHUNK_PIECES {
                break;
            }
            fetch_chunk(core, Tag::Fallback(leaf.start), &leaf.address).ok_or(Failure::Memory)?;
            leaf.state = LeafState::Fallback;
        }
        Ok(())
    }

    /// Delivers the passed leaves in order, trimmed to the body, until it
    /// is all out (`Ok(true)`); the first that failed, or the point the
    /// stream stopped at, ends the request.
    fn deliver(&mut self, core: &mut Core) -> Result<bool, Failure> {
        let from = self.stream_id();
        while let Some(front) = self.leaves.front() {
            match front.state {
                LeafState::Passed => {}
                LeafState::Failed(f) => return Err(f),
                LeafState::Filling => {
                    return match self.stopped.or_else(|| self.starved()) {
                        Some(f) => Err(f),
                        None => Ok(false),
                    };
                }
                _ => return Ok(false),
            }
            let Some(leaf) = self.leaves.pop_front() else {
                break;
            };
            let Some(bytes) = leaf.bytes else {
                // A passed leaf holds its bytes.
                return Err(Failure::Unverifiable);
            };
            let end = leaf.start + leaf.len as u64;
            let lo = self.a.max(leaf.start);
            let hi = (self.b + 1).min(end);
            let (keep_from, keep_to) = if hi > lo {
                (
                    usize::try_from(lo - leaf.start).unwrap_or(0),
                    usize::try_from(hi - leaf.start).unwrap_or(0),
                )
            } else {
                (0, 0)
            };
            let total = bytes.len();
            // Trimmed in place, and what it no longer holds released.
            let kept = bytes.keep(core, keep_from, keep_to);
            let n = kept.len();
            if let Some(id) = from {
                core.consumed(id, total - n);
            }
            self.released = end;
            core.body_charged(kept, from);
        }
        if self.released > self.b {
            return Ok(true);
        }
        if let Some(f) = self.stopped.or_else(|| self.starved()) {
            return Err(f);
        }
        if self.tree_done && self.leaves.is_empty() {
            // The tree ended before the body did: its geometry doesn't
            // cover the size its root declares.
            return Err(Failure::Unverifiable);
        }
        Ok(false)
    }

    /// The body goes: the stream closed and its frames dropped, then each
    /// leaf's and known chunk's buffer, then the tree, each before its
    /// charge.
    fn release_all(mut self, core: &mut Core) {
        self.close_stream(core);
        for leaf in std::mem::take(&mut self.leaves) {
            if let Some(bytes) = leaf.bytes {
                bytes.release(core);
            }
        }
        release_known(core, std::mem::take(&mut self.known));
        self.tree.release(core);
    }

    /// A leaf's bytes back from a job, in the state its check gave it.
    fn returned(&mut self, core: &mut Core, start: u64, bytes: Bytes, state: LeafState) {
        match self.leaves.iter_mut().find(|l| l.start == start) {
            Some(leaf) => {
                if let Some(old) = leaf.bytes.replace(bytes) {
                    old.release(core);
                }
                leaf.state = state;
            }
            None => bytes.release(core),
        }
    }

    fn whole(
        &mut self,
        core: &mut Core,
        tag: Tag,
        status: u16,
        body: Bytes,
    ) -> Result<bool, Failure> {
        match tag {
            Tag::Inter(start, depth) => {
                let Some((address, _)) = self.tree.address_of(start, depth) else {
                    body.release(core);
                    return Ok(false);
                };
                if status == 200 {
                    core.hash_charged(tag, body.map(|wire| Work::Chunk { address, wire }));
                } else {
                    body.release(core);
                    self.tree
                        .settle(core, start, depth, Err(Failure::Status(status)));
                }
            }
            Tag::Fallback(start) => {
                let Some(leaf) = self.leaves.iter_mut().find(|l| l.start == start) else {
                    body.release(core);
                    return Ok(false);
                };
                if status == 200 {
                    let bytes = match leaf.bytes.take() {
                        Some(bytes) => bytes,
                        None => Charged::new(core, Vec::new(), 0),
                    };
                    let (address, len) = (leaf.address, leaf.len);
                    core.hash_charged(
                        tag,
                        bytes.join(body).map(|(bytes, wire)| Work::LeafChunk {
                            address,
                            len,
                            bytes,
                            wire,
                        }),
                    );
                } else {
                    body.release(core);
                    leaf.state = LeafState::Failed(Failure::Status(status));
                }
            }
            _ => body.release(core),
        }
        self.pump(core)
    }

    fn failed(
        &mut self,
        core: &mut Core,
        tag: Tag,
        failure: PieceFailure,
    ) -> Result<bool, Failure> {
        match tag {
            Tag::Inter(start, depth) => {
                self.tree
                    .settle(core, start, depth, Err(Failure::Piece(failure)));
            }
            Tag::Fallback(start) => {
                if let Some(leaf) = self.leaves.iter_mut().find(|l| l.start == start) {
                    leaf.state = LeafState::Failed(Failure::Piece(failure));
                }
            }
            Tag::Bytes => self.stream_stopped(Failure::Piece(failure)),
            _ => {}
        }
        self.pump(core)
    }

    fn stream_stopped(&mut self, failure: Failure) {
        if let Some(s) = self.stream.as_mut() {
            s.open = false;
            if s.pos <= self.fe && self.ended.is_none() {
                self.ended = Some(failure);
            }
        }
    }

    /// The stream ended early and what it stashed is used up: the needed
    /// bytes it didn't send never come.
    fn starved(&self) -> Option<Failure> {
        let s = self.stream.as_ref()?;
        self.ended
            .filter(|_| s.stash.is_empty() && s.pos <= self.fe)
    }

    fn stream_head(
        &mut self,
        core: &mut Core,
        status: u16,
        headers: &[(String, String)],
    ) -> Result<bool, Failure> {
        let expected = format!("bytes {}-{}/{}", self.fs, self.fe, self.total);
        let Some(s) = self.stream.as_mut() else {
            return Ok(false);
        };
        s.headed = true;
        match status {
            206 if header(headers, "content-range") == Some(expected.as_str()) => s.pos = self.fs,
            200 => s.pos = 0,
            _ => {
                self.stopped = Some(Failure::Stopped);
                self.close_stream(core);
            }
        }
        self.pump(core)
    }

    fn stream_data(&mut self, core: &mut Core, bytes: Bytes) -> Result<bool, Failure> {
        match self.stream.as_mut() {
            Some(s) if s.open && s.headed => s.stash.push_back(bytes),
            Some(s) => {
                let n = bytes.len();
                bytes.release(core);
                core.consumed(s.id, n);
            }
            None => bytes.release(core),
        }
        self.pump(core)
    }

    fn stream_end(&mut self, core: &mut Core) -> Result<bool, Failure> {
        self.stream_stopped(Failure::Stopped);
        self.pump(core)
    }

    fn hashed(
        &mut self,
        core: &mut Core,
        tag: Tag,
        verdict: Verdict,
        work: Charged<Work>,
    ) -> Result<bool, Failure> {
        match (tag, verdict) {
            (Tag::Inter(start, depth), Verdict::Chunk(r)) => {
                if let Some((address, wire)) = chunk_work(core, work) {
                    if r.is_ok() {
                        remember(core, &address, &wire, false);
                    }
                    self.tree.settle(
                        core,
                        start,
                        depth,
                        r.map(|()| wire.as_slice()).map_err(refusal),
                    );
                    wire.release(core);
                }
            }
            (Tag::Leaf(start), Verdict::Leaf(matched)) => {
                if let Some(bytes) = leaf_work(core, work) {
                    let state = if matched {
                        LeafState::Passed
                    } else {
                        LeafState::NeedsFallback
                    };
                    self.returned(core, start, bytes, state);
                }
            }
            (Tag::Fallback(start), Verdict::LeafChunk(r)) => {
                if let Some(bytes) = leaf_work(core, work) {
                    let state = match r {
                        Ok(()) => LeafState::Passed,
                        Err(r) => LeafState::Failed(refusal(r)),
                    };
                    self.returned(core, start, bytes, state);
                }
            }
            _ => work.release(core),
        }
        self.pump(core)
    }
}

// ---------------------------------------------------------------------------
// The walk.

/// What a node load is for.
#[derive(Debug)]
enum Then {
    /// The URL's root.
    Root,
    /// A feed update's target.
    Target,
    /// A manifest node the lookup asked for: the lookup is the walk's.
    Child,
}

#[derive(Debug)]
enum Stage {
    Load {
        load: Load,
        then: Then,
    },
    FeedIndex {
        owner: [u8; 20],
        topic: [u8; 32],
    },
    FeedUpdate {
        owner: [u8; 20],
        topic: [u8; 32],
        index: u64,
    },
    FileRoot {
        entry: Charged<Entry>,
    },
    Body(Box<Body>),
    Done,
}

/// A lookup's step, read before it goes.
enum Stepped {
    /// The node at this reference; none when it isn't 32 bytes (an
    /// encrypted node).
    Need(Option<[u8; 32]>),
    Found,
    Ended(Ended),
}

/// How a lookup ended without an entry.
#[derive(Debug, Clone, Copy)]
enum Ended {
    NotFound { root: bool },
    Directory,
    Failed(NodeError),
    TooManyNodes,
}

/// The request's Swarm walk.
#[derive(Debug)]
pub(crate) struct Walk {
    root: [u8; 32],
    root_text: String,
    /// The path below the root, decoded as Ant's router decodes it.
    path: String,
    query: String,
    range: Option<String>,
    /// The URL root's chunk, once checked: a raw root's file root.
    url_root: Option<Bytes>,
    /// The feed the walk crossed.
    feed: Option<Feed>,
    /// A raw root's chunks the sniff checked, for its body.
    known: Known,
    stage: Stage,
    /// The manifest lookup, boxed, while it waits for a node, charged its
    /// root, the node it is at, the followed fork's metadata and its phases
    /// ([`Lookup::held`]).
    lookup: Option<Charged<Box<Lookup>>>,
}

impl Walk {
    pub(crate) fn start(
        core: &mut Core,
        root: &str,
        path: &str,
        query: &str,
        range: Option<String>,
    ) -> Result<Self, PlanRefusal> {
        let mut address = [0u8; 32];
        for (i, slot) in address.iter_mut().enumerate() {
            let pair = root.get(i * 2..i * 2 + 2).ok_or(PlanRefusal::Root)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| PlanRefusal::Root)?;
        }
        let below = path.strip_prefix('/').unwrap_or(path);
        let decoded = String::from_utf8(percent_decode(below));
        let mut walk = Self {
            root: address,
            root_text: root.to_owned(),
            path: decoded.clone().unwrap_or_default(),
            query: query.to_owned(),
            range,
            url_root: None,
            feed: None,
            known: Vec::new(),
            stage: Stage::Done,
            lookup: None,
        };
        if decoded.is_err() {
            core.fail(Failure::InvalidPath);
            return Ok(walk);
        }
        match Load::start(core, address) {
            Ok(load) => {
                walk.stage = Stage::Load {
                    load,
                    then: Then::Root,
                }
            }
            Err(f) => core.fail(f),
        }
        Ok(walk)
    }

    fn bare(&self) -> bool {
        self.path.trim_matches('/').is_empty()
    }

    fn label(&self) -> ContentTrust {
        if self.feed.is_some() {
            ContentTrust::LatestAsserted
        } else {
            ContentTrust::Verified
        }
    }

    /// Ends the request with `failure`, once all the walk holds has gone.
    fn end(&mut self, core: &mut Core, failure: Failure) {
        self.drop_all(core);
        core.fail(failure);
    }

    /// Everything the walk holds goes, each before its charge: the stage,
    /// the lookup, the URL root's chunk and the sniff's.
    fn drop_all(&mut self, core: &mut Core) {
        self.drop_stage(core);
        if let Some(lookup) = self.lookup.take() {
            lookup.release(core);
        }
        self.release_url_root(core);
    }

    fn drop_stage(&mut self, core: &mut Core) {
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::Load { load, .. } => load.release(core),
            Stage::FileRoot { entry } => entry.release(core),
            Stage::Body(body) => (*body).release_all(core),
            _ => {}
        }
    }

    fn release_url_root(&mut self, core: &mut Core) {
        if let Some(wire) = self.url_root.take() {
            wire.release(core);
        }
        release_known(core, std::mem::take(&mut self.known));
    }

    /// A lookup for the path below `node`, a parsed node under its charge:
    /// room for the lookup, its box and its first step is reserved first,
    /// and with the node's charge covers them until the step is taken
    /// ([`Walk::step`]).
    fn start_lookup(&mut self, core: &mut Core, node: Charged<manifest::Node>) {
        let Some(room) = Charged::room(core, manifest::lookup_room(&self.path)) else {
            node.release(core);
            return self.end(core, Failure::Memory);
        };
        let path = &self.path;
        let taken = node.join(room).map(|(node, ())| {
            let (lookup, step) = Lookup::new(node, path);
            (Box::new(lookup), step)
        });
        self.step(core, taken);
    }

    /// A proven answer with a fixed body: a 404, a 308 or a 416. Room for
    /// its head's headers and its body, beside what `cover` holds for
    /// them, is reserved before the head promises the body.
    fn answer(
        &mut self,
        core: &mut Core,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        content: ContentTrust,
        cover: Option<Charged<()>>,
    ) {
        self.drop_all(core);
        let mut cover = match cover {
            Some(c) => c,
            None => Charged::new(core, (), 0),
        };
        let need = super::headers_cost(&headers) + body.len();
        match Charged::room(core, need.saturating_sub(cover.cost())) {
            Some(more) => cover = cover.join(more).map(|((), ())| ()),
            None => {
                drop(headers);
                drop(body);
                cover.release(core);
                return core.fail(Failure::Memory);
            }
        }
        let n = body.len();
        let body = cover.split(n).map(|()| body);
        if core.head_only {
            // Nothing follows a HEAD's head, which ends the request.
            body.release(core);
            return core.head_charged(status, headers, content, cover);
        }
        core.head_charged(status, headers, content, cover);
        core.body_charged(body, None);
        core.finish();
    }

    fn not_found(&mut self, core: &mut Core, kind: NotFound, content: ContentTrust) {
        let (h, body) = ant::not_found(kind);
        self.answer(core, 404, h, body, content, None);
    }

    /// The entry for the URL reference's own bytes, its name from the path.
    fn bare_entry(&self, core: &mut Core) -> Charged<Entry> {
        let entry = Entry {
            content_type: None,
            filename: ant::filename_from_path(&self.path),
            reference: self.root,
            feed: None,
        };
        Charged::measured(core, entry)
    }

    /// Ant's fallback for a node that isn't a manifest: a bare request gets
    /// the URL reference's own bytes; any path below it, a 404.
    fn raw_fallback(&mut self, core: &mut Core) {
        if !self.bare() {
            let label = self.label();
            return self.not_found(core, NotFound::Path, label);
        }
        self.drop_stage(core);
        if let Some(lookup) = self.lookup.take() {
            lookup.release(core);
        }
        let Some(wire) = self.url_root.take() else {
            return self.end(core, Failure::Unverifiable);
        };
        let entry = self.bare_entry(core);
        // Those bytes are the URL reference's own: verified.
        self.feed = None;
        self.root_passed(core, entry, wire);
    }

    fn loaded(&mut self, core: &mut Core, then: Then, loaded: Loaded, root_wire: Option<Bytes>) {
        match then {
            Then::Root => {
                if let Some(w) = root_wire
                    && let Some(old) = self.url_root.replace(w)
                {
                    old.release(core);
                }
                match loaded {
                    Loaded::NotAManifest => {
                        let Some(wire) = self.url_root.take() else {
                            return self.end(core, Failure::Unverifiable);
                        };
                        if !self.bare() {
                            wire.release(core);
                            return self.not_found(core, NotFound::Path, ContentTrust::Verified);
                        }
                        let entry = self.bare_entry(core);
                        self.root_passed(core, entry, wire);
                    }
                    Loaded::TooLarge => self.end(core, Failure::Unverifiable),
                    Loaded::Node(bytes) => self.root_node(core, bytes),
                }
            }
            Then::Target => {
                if let Some(w) = root_wire {
                    w.release(core);
                }
                match loaded {
                    Loaded::NotAManifest => self.raw_fallback(core),
                    Loaded::TooLarge => self.end(core, Failure::Unverifiable),
                    Loaded::Node(bytes) => match parse(core, bytes) {
                        Err(f) => self.end(core, f),
                        Ok(Ok(node)) => self.start_lookup(core, node),
                        Ok(Err(NodeError::NotAManifest)) => self.raw_fallback(core),
                        Ok(Err(NodeError::Malformed)) => {
                            let label = self.label();
                            self.not_found(core, NotFound::Plain, label);
                        }
                        Ok(Err(NodeError::TooLarge)) => self.end(core, Failure::Unverifiable),
                    },
                }
            }
            Then::Child => {
                if let Some(w) = root_wire {
                    w.release(core);
                }
                if matches!(loaded, Loaded::TooLarge) {
                    return self.end(core, Failure::Unverifiable);
                }
                // The lookup's step, within room reserved for what it
                // parses and copies.
                let parse_room = match &loaded {
                    Loaded::Node(bytes) => manifest::parse_room(bytes.len()),
                    _ => 0,
                };
                let Some(room) = Charged::room(core, parse_room + manifest::STEP_ROOM) else {
                    loaded.release(core);
                    return self.end(core, Failure::Memory);
                };
                let Some(lookup) = self.lookup.take() else {
                    loaded.release(core);
                    room.release(core);
                    return self.end(core, Failure::Unverifiable);
                };
                // The room, the node's bytes and the lookup's charge cover
                // the step until it is taken.
                let taken = match loaded {
                    Loaded::Node(bytes) => {
                        lookup
                            .join(room)
                            .join(bytes)
                            .map(|((mut lookup, ()), bytes)| {
                                let step = lookup.node(bytes);
                                (lookup, step)
                            })
                    }
                    _ => lookup.join(room).map(|(mut lookup, ())| {
                        let step = lookup.refused(NodeError::NotAManifest);
                        (lookup, step)
                    }),
                };
                self.step(core, taken);
            }
        }
    }

    /// The URL root's node: a feed, or the manifest to look the path up in.
    fn root_node(&mut self, core: &mut Core, bytes: Bytes) {
        let node = match parse(core, bytes) {
            Err(f) => return self.end(core, f),
            Ok(Ok(n)) => n,
            Ok(Err(NodeError::NotAManifest)) => {
                return self.loaded(core, Then::Root, Loaded::NotAManifest, None);
            }
            Ok(Err(NodeError::Malformed)) => {
                return self.not_found(core, NotFound::Plain, ContentTrust::Verified);
            }
            Ok(Err(NodeError::TooLarge)) => return self.end(core, Failure::Unverifiable),
        };
        let feed = node
            .forks
            .iter()
            .find(|f| f.byte == b'/')
            .map_or(Ok(None), |f| feed_of(&f.metadata));
        if matches!(feed, Ok(None)) {
            return self.start_lookup(core, node);
        }
        // A feed, or metadata Ant refuses: the node isn't needed any more.
        node.release(core);
        match feed {
            Ok(Some((owner, topic))) => {
                let mut headers = chunk_headers();
                headers.push(("swarm-only-root-chunk".to_owned(), "true".to_owned()));
                let path = format!("/feeds/{}/{}", ant::hex(&owner), ant::hex(&topic));
                if core
                    .fetch(Tag::Feed, path, headers, Ask::Whole(super::MAX_WHOLE))
                    .is_none()
                {
                    return self.end(core, Failure::Memory);
                }
                self.stage = Stage::FeedIndex { owner, topic };
            }
            // Looked up above.
            Ok(None) => {}
            // Feed metadata Ant refuses: its lookup error is a bare 404.
            Err(()) => self.not_found(core, NotFound::Plain, ContentTrust::Verified),
        }
    }

    /// The lookup's step, `taken` with the lookup under one charge, which
    /// covers what the step allocated: the parsed node, the lookup's growth
    /// and the step itself. The charge moves on only once what it covers
    /// has gone, or is measured again: to the boxed lookup while it waits
    /// for a node, or to the entry while the file's root chunk is fetched.
    fn step(&mut self, core: &mut Core, taken: Charged<(Box<Lookup>, Step)>) {
        let label = self.label();
        let stepped = match &taken.1 {
            Step::Need(reference) => Stepped::Need(<[u8; 32]>::try_from(reference.as_slice()).ok()),
            Step::Done(Outcome::Found { .. }) => Stepped::Found,
            Step::Done(Outcome::NotFound { root }) => {
                Stepped::Ended(Ended::NotFound { root: *root })
            }
            Step::Done(Outcome::Directory) => Stepped::Ended(Ended::Directory),
            Step::Failed(e) => Stepped::Ended(Ended::Failed(*e)),
            Step::TooManyNodes => Stepped::Ended(Ended::TooManyNodes),
        };
        match stepped {
            Stepped::Need(address) => {
                // What lasts while the next node loads: the boxed lookup.
                // The step goes, and the rest of the charge after it.
                let lookup = taken.remake(core, |(lookup, step)| {
                    drop(step);
                    lookup
                });
                if let Some(old) = self.lookup.replace(lookup) {
                    old.release(core);
                }
                let Some(address) = address else {
                    // A 64-byte reference: an encrypted node.
                    return self.end(core, Failure::Unverifiable);
                };
                match Load::start(core, address) {
                    Ok(load) => {
                        self.stage = Stage::Load {
                            load,
                            then: Then::Child,
                        }
                    }
                    Err(f) => self.end(core, f),
                }
            }
            Stepped::Found => {
                // The lookup goes; the charge covers its outcome until the
                // entry takes it over.
                let found = taken.map(|(lookup, step)| {
                    drop(lookup);
                    match step {
                        Step::Done(Outcome::Found { data_ref, metadata }) => (data_ref, metadata),
                        _ => (Vec::new(), Metadata::default()),
                    }
                });
                self.found(core, found);
            }
            Stepped::Ended(ended) => {
                taken.release(core);
                self.outcome(core, ended, label);
            }
        }
    }

    /// The lookup found the entry, its data reference and metadata under
    /// the step's charge: the reference is copied out and its vector
    /// dropped, the metadata's strings move into the entry (a filename from
    /// the path, when it has none, within room reserved first), and the
    /// charge, measured as the entry, is its own while the file's root
    /// chunk is fetched.
    fn found(&mut self, core: &mut Core, found: Charged<(Vec<u8>, Metadata)>) {
        let found = found.map(|(data_ref, metadata)| {
            let reference = <[u8; 32]>::try_from(data_ref.as_slice()).ok();
            drop(data_ref);
            (reference, metadata)
        });
        let Some(reference) = found.0 else {
            found.release(core);
            return self.end(core, Failure::Unverifiable);
        };
        let Some(room) = Charged::room(core, self.path.len()) else {
            found.release(core);
            return self.end(core, Failure::Memory);
        };
        let (path, feed) = (&self.path, self.feed);
        let entry = found.join(room).remake(core, |((_, mut metadata), ())| {
            let content_type = take(&mut metadata, manifest::CONTENT_TYPE);
            let filename =
                take(&mut metadata, manifest::FILENAME).or_else(|| ant::filename_from_path(path));
            drop(metadata);
            Entry {
                content_type,
                filename,
                reference,
                feed,
            }
        });
        self.release_url_root(core);
        // Staged first, so an end from here releases the entry.
        self.stage = Stage::FileRoot { entry };
        if fetch_chunk(core, Tag::FileRoot, &reference).is_none() {
            self.end(core, Failure::Memory);
        }
    }

    /// Where a lookup ended without an entry, its charge released.
    fn outcome(&mut self, core: &mut Core, ended: Ended, label: ContentTrust) {
        match ended {
            Ended::NotFound { root } => {
                let kind = if root { NotFound::Root } else { NotFound::Path };
                self.not_found(core, kind, label);
            }
            Ended::Directory => {
                let (h, body) =
                    ant::redirect(&self.root_text, &self.path, &self.query, core.head_only);
                self.answer(core, 308, h, body, label, None);
            }
            Ended::Failed(NodeError::NotAManifest) => self.raw_fallback(core),
            Ended::Failed(NodeError::Malformed) => self.not_found(core, NotFound::Plain, label),
            Ended::Failed(NodeError::TooLarge) | Ended::TooManyNodes => {
                self.end(core, Failure::Unverifiable);
            }
        }
    }

    /// The file's root chunk passed for `entry`. The head copies its
    /// strings, a filename escaped to at most twice its length: room for
    /// that is reserved first, and becomes the head's.
    fn root_passed(&mut self, core: &mut Core, entry: Charged<Entry>, wire: Bytes) {
        let Some(room) = Charged::room(core, 2 * entry.cost() + HEAD_ROOM) else {
            entry.release(core);
            wire.release(core);
            return self.end(core, Failure::Memory);
        };
        // A raw root's sniffed chunks go to its body.
        let known = std::mem::take(&mut self.known);
        self.release_url_root(core);
        self.file_body(core, entry, room, wire, known);
    }

    /// The head, made within `room`, then the body. What the head doesn't
    /// need goes before it, so a head that ends the request (a HEAD, or no
    /// body) leaves nothing behind.
    fn file_body(
        &mut self,
        core: &mut Core,
        entry: Charged<Entry>,
        room: Charged<()>,
        wire: Bytes,
        known: Known,
    ) {
        let Some(chunk) = chunk_view(&wire) else {
            entry.release(core);
            room.release(core);
            wire.release(core);
            release_known(core, known);
            return self.end(core, Failure::VerificationFailed);
        };
        // Ant's size: the span with its top byte masked.
        let mut masked = chunk.span;
        masked[SPAN_SIZE - 1] = 0;
        let total = u64::from_le_bytes(masked);
        let (level, logical) = tree::decode_span(&chunk.span);
        let payload = chunk.payload.len();
        let content = if entry.feed.is_some() {
            ContentTrust::LatestAsserted
        } else {
            ContentTrust::Verified
        };
        let leaf = tree::is_leaf(logical);
        if logical != total || (leaf && payload < usize::try_from(total).unwrap_or(usize::MAX)) {
            // A span Ant reads otherwise than its joiner, or a single-chunk
            // file shorter than its span.
            entry.release(core);
            room.release(core);
            wire.release(core);
            release_known(core, known);
            return self.end(core, Failure::Unverifiable);
        }
        let ranges = if core.head_only {
            Ranges::Full
        } else {
            ant::parse_ranges(self.range.as_deref(), total)
        };
        let (status, headers, a, b) = match ranges {
            Ranges::Invalid | Ranges::NoOverlap => {
                let t = (ranges == Ranges::NoOverlap).then_some(total);
                let (h, body) = ant::not_satisfiable(t, entry.filename.as_deref());
                let body = body.to_vec();
                entry.release(core);
                wire.release(core);
                release_known(core, known);
                return self.answer(core, 416, h, body, content, Some(room));
            }
            Ranges::Single { start, length: 0 } => {
                let h = ant::zero_length(&entry, total, start);
                entry.release(core);
                wire.release(core);
                release_known(core, known);
                core.head_charged(206, h, content, room);
                return core.finish();
            }
            Ranges::Single { start, length } => (
                206,
                ant::partial(&entry, total, start, start + length - 1),
                start,
                start + length - 1,
            ),
            Ranges::Full | Ranges::Multi => {
                let h = ant::whole(&entry, total, core.head_only);
                if total == 0 {
                    entry.release(core);
                    wire.release(core);
                    release_known(core, known);
                    core.head_charged(200, h, content, room);
                    return core.finish();
                }
                (200, h, 0, total - 1)
            }
        };
        let reference = entry.reference;
        entry.release(core);
        if core.head_only {
            // A HEAD: nothing past the file's root is read.
            wire.release(core);
            release_known(core, known);
            return core.head_charged(status, headers, content, room);
        }
        core.head_charged(status, headers, content, room);
        if leaf {
            release_known(core, known);
            let s = usize::try_from(a).unwrap_or(0);
            let e = usize::try_from(b).unwrap_or(0) + 1;
            // The range, cut from the wire in place.
            let bytes = wire.keep(core, SPAN_SIZE + s, SPAN_SIZE + e);
            core.body_charged(bytes, None);
            return core.finish();
        }
        let block = CHUNK_SIZE as u64;
        let fs = a / block * block;
        let fe = ((b / block + 1) * block).min(total) - 1;
        let branching = if level == 0 {
            tree::MAX_REFS
        } else {
            tree::max_shards(level)
        } as u64;
        let tree = Tree::new(core, &wire, total, a, b + 1, 2 * branching * block);
        wire.release(core);
        let tree = match tree {
            Ok(t) => t,
            Err(f) => {
                release_known(core, known);
                return self.end(core, f);
            }
        };
        let mut body = Box::new(Body {
            reference,
            tree,
            a,
            b,
            fs,
            fe,
            total,
            stream: None,
            leaves: VecDeque::new(),
            tree_done: false,
            stopped: None,
            ended: None,
            released: fs,
            known,
        });
        let r = body.pump(core);
        self.stage = Stage::Body(body);
        self.body_result(core, r);
    }

    // Events, from the machine.

    pub(crate) fn whole(
        &mut self,
        core: &mut Core,
        tag: Tag,
        status: u16,
        headers: &[(String, String)],
        body: Bytes,
    ) {
        match &mut self.stage {
            Stage::Load { load, .. } => {
                let p = load.whole(core, tag, status, body);
                self.progress(core, p);
            }
            Stage::FeedIndex { owner, topic } if tag == Tag::Feed => {
                let (owner, topic) = (*owner, *topic);
                // The index is in its headers; its bytes aren't read.
                body.release(core);
                if let Err(f) = ok_status(status) {
                    return self.end(core, f);
                }
                let index = header(headers, "swarm-feed-index").and_then(feed_index);
                let Some(index) = index else {
                    return self.end(core, Failure::VerificationFailed);
                };
                let address = fc_swarm::verify::feed_update_address(&owner, &topic, index);
                if fetch_chunk(core, Tag::Update, &address).is_none() {
                    return self.end(core, Failure::Memory);
                }
                self.stage = Stage::FeedUpdate {
                    owner,
                    topic,
                    index,
                };
            }
            Stage::FeedUpdate {
                owner,
                topic,
                index,
            } if tag == Tag::Update => {
                let (owner, topic, index) = (*owner, *topic, *index);
                if let Err(f) = ok_status(status) {
                    body.release(core);
                    return self.end(core, f);
                }
                let work = body.map(|wire| Work::FeedUpdate {
                    owner,
                    topic,
                    index,
                    wire,
                });
                core.hash_charged(tag, work);
            }
            Stage::FileRoot { entry } if tag == Tag::FileRoot => {
                let address = entry.reference;
                if let Err(f) = ok_status(status) {
                    body.release(core);
                    return self.end(core, f);
                }
                core.hash_charged(tag, body.map(|wire| Work::Chunk { address, wire }));
            }
            Stage::Body(b) => {
                let r = b.whole(core, tag, status, body);
                self.body_result(core, r);
            }
            _ => body.release(core),
        }
    }

    pub(crate) fn failed(&mut self, core: &mut Core, tag: Tag, failure: PieceFailure) {
        match &mut self.stage {
            Stage::Body(b) => {
                let r = b.failed(core, tag, failure);
                self.body_result(core, r);
            }
            Stage::Done => {}
            _ => self.end(core, Failure::Piece(failure)),
        }
    }

    pub(crate) fn stream_head(
        &mut self,
        core: &mut Core,
        tag: Tag,
        _id: PieceId,
        status: u16,
        headers: &[(String, String)],
    ) {
        if let (Stage::Body(b), Tag::Bytes) = (&mut self.stage, tag) {
            let r = b.stream_head(core, status, headers);
            self.body_result(core, r);
        }
    }

    pub(crate) fn stream_data(&mut self, core: &mut Core, tag: Tag, id: PieceId, bytes: Bytes) {
        if let (Stage::Body(b), Tag::Bytes) = (&mut self.stage, tag) {
            let r = b.stream_data(core, bytes);
            self.body_result(core, r);
        } else {
            let n = bytes.len();
            bytes.release(core);
            core.consumed(id, n);
        }
    }

    pub(crate) fn stream_end(&mut self, core: &mut Core, tag: Tag, _id: PieceId) {
        if let (Stage::Body(b), Tag::Bytes) = (&mut self.stage, tag) {
            let r = b.stream_end(core);
            self.body_result(core, r);
        }
    }

    pub(crate) fn hashed(
        &mut self,
        core: &mut Core,
        tag: Tag,
        verdict: Verdict,
        work: Charged<Work>,
    ) {
        match &mut self.stage {
            Stage::Load { load, .. } => {
                let p = load.hashed(core, tag, verdict, work);
                self.progress(core, p);
            }
            Stage::FeedUpdate { index, .. } if tag == Tag::Update => {
                let index = *index;
                let Verdict::FeedUpdate(result) = verdict else {
                    work.release(core);
                    return self.end(core, Failure::Unverifiable);
                };
                let wire = work.try_map(core, |w| match w {
                    Work::FeedUpdate { wire, .. } => Some(wire),
                    _ => None,
                });
                let Some(wire) = wire else {
                    return self.end(core, Failure::Unverifiable);
                };
                match result {
                    Err(r) => {
                        wire.release(core);
                        self.end(core, refusal(r));
                    }
                    Ok(FeedUpdate::V1 { reference, .. }) => {
                        wire.release(core);
                        self.feed = Some(Feed { index, v2: false });
                        match Load::start(core, reference) {
                            Ok(load) => {
                                self.stage = Stage::Load {
                                    load,
                                    then: Then::Target,
                                }
                            }
                            Err(f) => self.end(core, f),
                        }
                    }
                    Ok(FeedUpdate::V2 { root, .. }) => {
                        self.feed = Some(Feed { index, v2: true });
                        // The update wraps the target's root chunk itself,
                        // checked against its address with the signature:
                        // its identifier and signature are cut off in place.
                        let wrapped = wire.map(|mut w| {
                            w.drain(..(32 + 65).min(w.len()));
                            w
                        });
                        let (load, p) = Load::with_root(core, root, wrapped);
                        self.stage = Stage::Load {
                            load,
                            then: Then::Target,
                        };
                        self.progress(core, p);
                    }
                }
            }
            Stage::FileRoot { .. } if tag == Tag::FileRoot => {
                let Verdict::Chunk(result) = verdict else {
                    work.release(core);
                    return self.end(core, Failure::Unverifiable);
                };
                let Some((address, wire)) = chunk_work(core, work) else {
                    return self.end(core, Failure::Unverifiable);
                };
                if let Err(r) = result {
                    wire.release(core);
                    return self.end(core, refusal(r));
                }
                // A file's root is structure when it is intermediate.
                remember(core, &address, &wire, false);
                let Stage::FileRoot { entry } = std::mem::replace(&mut self.stage, Stage::Done)
                else {
                    return wire.release(core);
                };
                self.root_passed(core, entry, wire);
            }
            Stage::Body(b) => {
                let r = b.hashed(core, tag, verdict, work);
                self.body_result(core, r);
            }
            _ => work.release(core),
        }
    }

    /// A body's move: an error ends the request; once the body is all out,
    /// it goes, with all the walk holds, before the request finishes.
    fn body_result(&mut self, core: &mut Core, r: Result<bool, Failure>) {
        match r {
            Err(f) => self.end(core, f),
            Ok(true) => {
                self.drop_all(core);
                core.finish();
            }
            Ok(false) => {
                if core.ended() {
                    self.drop_all(core);
                }
            }
        }
    }

    fn progress(&mut self, core: &mut Core, p: Progress) {
        match p {
            Progress::Pending => {}
            Progress::Failed(f) => self.end(core, f),
            Progress::Loaded(loaded) => {
                let Stage::Load { mut load, then } =
                    std::mem::replace(&mut self.stage, Stage::Done)
                else {
                    return loaded.release(core);
                };
                // The root chunk and a node's bytes go to the caller under
                // their charges; the rest goes.
                let root = load.root.take();
                let known = std::mem::take(&mut load.known);
                load.release(core);
                if matches!((&then, &loaded), (Then::Root, Loaded::NotAManifest)) {
                    release_known(core, std::mem::replace(&mut self.known, known));
                } else {
                    release_known(core, known);
                }
                self.loaded(core, then, loaded, root);
            }
        }
    }
}

/// Ant's `feed_from_metadata`: `None` when the `/` fork names no owner,
/// `Err` for feed metadata it refuses.
/// A feed's owner and topic.
type FeedKey = ([u8; 20], [u8; 32]);

/// Parses a loaded node's bytes, under their charge, within the request's
/// memory: room for the node is reserved first; the bytes are parsed in
/// place, and the node alone is charged once it is made. Without the room,
/// the walk is past its memory.
fn parse(
    core: &mut Core,
    bytes: Bytes,
) -> Result<Result<Charged<manifest::Node>, NodeError>, Failure> {
    let Some(room) = Charged::room(core, manifest::parse_room(bytes.len())) else {
        bytes.release(core);
        return Err(Failure::Memory);
    };
    Ok(bytes
        .join(room)
        .remake(core, |(bytes, ())| manifest::parse_node_owned(bytes))
        .transpose(core))
}

fn feed_of(meta: &manifest::Metadata) -> Result<Option<FeedKey>, ()> {
    let Some(owner) = meta.get(manifest::FEED_OWNER) else {
        return Ok(None);
    };
    let topic = meta.get(manifest::FEED_TOPIC).ok_or(())?;
    match meta.get(manifest::FEED_TYPE) {
        None | Some("Sequence" | "sequence") => {}
        Some(_) => return Err(()),
    }
    let owner = hex_array(owner.trim_start_matches("0x")).ok_or(())?;
    let topic = hex_array(topic.trim_start_matches("0x")).ok_or(())?;
    Ok(Some((owner, topic)))
}

/// `s` as exactly `N` bytes of hex, decoded into place: no allocation.
fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A metadata key's value, moved out: its string, not a copy.
fn take(metadata: &mut Metadata, key: &str) -> Option<String> {
    metadata
        .0
        .iter_mut()
        .find(|(k, _)| k == key)
        .map(|(_, v)| std::mem::take(v))
}

/// `swarm-feed-index`: the update's index as 16 hex digits.
fn feed_index(value: &str) -> Option<u64> {
    if value.len() != 16 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(value, 16).ok()
}

/// The machine's inputs, each value under the charge the machine took for
/// it as it came.
impl super::Events<Tag> for Walk {
    fn audit(&self, core: &mut Core) {
        core.audit_charged();
    }

    fn whole(
        &mut self,
        core: &mut Core,
        tag: Tag,
        status: u16,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) {
        let n = body.len();
        let body = Charged::arrived(core, body, n);
        Walk::whole(self, core, tag, status, headers, body);
    }

    fn stream_head(
        &mut self,
        core: &mut Core,
        tag: Tag,
        id: PieceId,
        status: u16,
        headers: &[(String, String)],
    ) {
        Walk::stream_head(self, core, tag, id, status, headers);
    }

    fn stream_data(&mut self, core: &mut Core, tag: Tag, id: PieceId, bytes: Vec<u8>) {
        let n = bytes.len();
        let bytes = Charged::arrived(core, bytes, n);
        Walk::stream_data(self, core, tag, id, bytes);
    }

    fn stream_end(&mut self, core: &mut Core, tag: Tag, id: PieceId) {
        Walk::stream_end(self, core, tag, id);
    }

    fn failed(&mut self, core: &mut Core, tag: Tag, failure: PieceFailure) {
        Walk::failed(self, core, tag, failure);
    }

    fn hashed(&mut self, core: &mut Core, tag: Tag, verdict: Verdict, work: Work) {
        let n = work.size();
        let work = Charged::arrived(core, work, n);
        Walk::hashed(self, core, tag, verdict, work);
    }
}
