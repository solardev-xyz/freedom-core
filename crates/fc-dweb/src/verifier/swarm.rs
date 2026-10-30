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
use fc_swarm::manifest::{self, Lookup, NodeError, Outcome, Step};
use fc_swarm::tree;
use fc_swarm::verify::{Chunk, FeedUpdate, MAX_CHUNK_WIRE, Refusal, SPAN_SIZE};

use super::ant::{self, Entry, Feed, NotFound, Ranges};
use super::jobs::{Verdict, Work};
use super::{Core, Failure, MAX_CHUNK_PIECES, PieceFailure, PieceId};
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
        false,
        SOC_MAX,
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

    fn cost(&self) -> usize {
        self.children.len() * CHILD_COST
    }
}

#[derive(Debug)]
enum Ahead {
    /// Asked for, or being hashed.
    Fetching {
        address: [u8; 32],
        len: u64,
    },
    Ready(Frame),
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
    stack: Vec<Frame>,
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
        let frame = Frame::parse(root, 0, len, 0)?;
        core.hold(frame.cost());
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
                    core.unhold(f.cost());
                }
                continue;
            }
            let (address, len) = top.children[top.next];
            let start = top.pos;
            let depth = top.depth + 1;
            if len == 0 || start + len <= self.from {
                top.next += 1;
                top.pos += len;
                continue;
            }
            if tree::is_leaf(len) {
                top.next += 1;
                top.pos += len;
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
                    top.next += 1;
                    top.pos += len;
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

    /// Asks for what [`Tree::wants`], within the chunk requests' bound,
    /// taking chunks already checked from `known` (each used once, and its
    /// holding released); the one the cursor waits for must fit the
    /// request's memory.
    fn fetch(
        &mut self,
        core: &mut Core,
        known: &mut Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), Failure> {
        for w in self.wants() {
            let (start, depth) = (w.start, w.depth);
            self.ahead.insert(
                (start, depth),
                Ahead::Fetching {
                    address: w.address,
                    len: w.len,
                },
            );
            if let Some(i) = known.iter().position(|(a, _)| *a == w.address) {
                let (_, wire) = known.swap_remove(i);
                self.settle(core, start, depth, Ok(&wire));
                core.unhold(wire.len());
                continue;
            }
            if core.whole_pieces() >= MAX_CHUNK_PIECES {
                self.ahead.remove(&(start, depth));
                break;
            }
            if fetch_chunk(core, Tag::Inter(start, depth), &w.address).is_none() {
                self.ahead.remove(&(start, depth));
                if w.blocking {
                    return Err(Failure::Unverifiable);
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
            Ok(frame) => {
                core.hold(frame.cost());
                Ahead::Ready(frame)
            }
            Err(f) => Ahead::Failed(f),
        };
        self.ahead.insert((start, depth), entry);
    }

    fn release(&mut self, core: &mut Core) {
        for f in self.stack.drain(..) {
            core.unhold(f.cost());
        }
        for (_, a) in std::mem::take(&mut self.ahead) {
            if let Ahead::Ready(f) = a {
                core.unhold(f.cost());
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
    Node(Vec<u8>),
    /// Ant's sniff found its first data chunk without a version hash.
    NotAManifest,
    /// A manifest node past the core's 1 MiB.
    TooLarge,
}

#[derive(Debug)]
enum LoadState {
    Root,
    /// Descending the leftmost references: `at` is the chunk in hand.
    Sniff {
        depth: usize,
        child: [u8; 32],
    },
    Join(Join),
}

#[derive(Debug)]
struct Join {
    buf: Vec<u8>,
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
    root: Option<Vec<u8>>,
    /// Chunks the sniff checked, which the join reuses.
    known: Vec<([u8; 32], Vec<u8>)>,
}

enum Progress {
    Pending,
    Loaded(Loaded),
    Failed(Failure),
}

impl Load {
    fn start(core: &mut Core, address: [u8; 32]) -> Result<Self, Failure> {
        fetch_chunk(core, Tag::NodeRoot, &address).ok_or(Failure::Unverifiable)?;
        Ok(Self {
            address,
            state: LoadState::Root,
            root: None,
            known: Vec::new(),
        })
    }

    /// A load whose root chunk is in hand and checked: a v2 feed update's.
    fn with_root(core: &mut Core, address: [u8; 32], wire: Vec<u8>) -> (Self, Progress) {
        let mut load = Self {
            address,
            state: LoadState::Root,
            root: None,
            known: Vec::new(),
        };
        let p = load.rooted(core, wire);
        (load, p)
    }

    fn held(&self) -> usize {
        let join = match &self.state {
            LoadState::Join(j) => j.buf.len(),
            _ => 0,
        };
        self.root.as_ref().map_or(0, Vec::len)
            + self.known.iter().map(|(_, w)| w.len()).sum::<usize>()
            + join
    }

    /// Drops what the load holds, and its tree's frames.
    fn release(&mut self, core: &mut Core) {
        core.unhold(self.held());
        if let LoadState::Join(j) = &mut self.state {
            j.tree.release(core);
        }
        self.root = None;
        self.known.clear();
        self.state = LoadState::Root;
    }

    /// The root chunk passed.
    fn rooted(&mut self, core: &mut Core, wire: Vec<u8>) -> Progress {
        self.root = Some(wire.clone());
        core.hold(wire.len());
        self.sniff_from(core, wire, 0)
    }

    /// Ant's `leftmost_leaf_is_not_a_manifest`, from the chunk in hand.
    fn sniff_from(&mut self, core: &mut Core, wire: Vec<u8>, depth: usize) -> Progress {
        let mut chunk = wire;
        let mut depth = depth;
        loop {
            if depth >= SNIFF_DEPTH {
                return self.join(core);
            }
            let payload = &chunk[SPAN_SIZE.min(chunk.len())..];
            if span_of(&chunk) <= CHUNK_SIZE as u64 {
                let raw = payload.len() < NODE_HEADER || !manifest::has_manifest_header(payload);
                if raw {
                    return Progress::Loaded(Loaded::NotAManifest);
                }
                return self.join(core);
            }
            let Some(child) = payload.get(..32).and_then(|c| <[u8; 32]>::try_from(c).ok()) else {
                return self.join(core);
            };
            if let Some((_, w)) = self.known.iter().find(|(a, _)| *a == child) {
                chunk = w.clone();
                depth += 1;
                continue;
            }
            if fetch_chunk(core, Tag::Sniff, &child).is_none() {
                return Progress::Failed(Failure::Unverifiable);
            }
            self.state = LoadState::Sniff { depth, child };
            return Progress::Pending;
        }
    }

    /// The node is a manifest, or may be one: join it, within 1 MiB.
    fn join(&mut self, core: &mut Core) -> Progress {
        let Some(root) = self.root.clone() else {
            return Progress::Failed(Failure::Unverifiable);
        };
        let len = span_of(&root);
        let Ok(size) = usize::try_from(len) else {
            return Progress::Loaded(Loaded::TooLarge);
        };
        if size > manifest::MAX_NODE {
            return Progress::Loaded(Loaded::TooLarge);
        }
        if tree::is_leaf(len) {
            let payload = &root[SPAN_SIZE..];
            return match payload.get(..size) {
                Some(bytes) => {
                    core.hold(size);
                    Progress::Loaded(Loaded::Node(bytes.to_vec()))
                }
                None => Progress::Failed(Failure::Unverifiable),
            };
        }
        if !core.fits(size) {
            return Progress::Failed(Failure::Unverifiable);
        }
        core.hold(size);
        let tree = match Tree::new(core, &root, len, 0, len, u64::MAX) {
            Ok(t) => t,
            Err(f) => {
                core.unhold(size);
                return Progress::Failed(f);
            }
        };
        self.state = LoadState::Join(Join {
            buf: vec![0; size],
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
                            let w = w.clone();
                            if let Err(f) = Self::place(join, start, len, &w) {
                                return Progress::Failed(f);
                            }
                            continue;
                        }
                        if fetch_chunk(core, Tag::JoinLeaf(start), &address).is_none() {
                            return Progress::Failed(Failure::Unverifiable);
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
                let bytes = std::mem::take(&mut join.buf);
                join.tree.release(core);
                // The buffer's holding moves to the caller with the bytes.
                self.state = LoadState::Root;
                return Progress::Loaded(Loaded::Node(bytes));
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
            .get_mut(s..s + n)
            .ok_or(Failure::Unverifiable)?
            .copy_from_slice(bytes);
        Ok(())
    }

    fn whole(&mut self, core: &mut Core, tag: Tag, status: u16, body: Vec<u8>) -> Progress {
        if let Err(f) = ok_status(status) {
            core.unhold(body.len());
            return Progress::Failed(f);
        }
        let address = match (tag, &self.state) {
            (Tag::NodeRoot, LoadState::Root) => self.address,
            (Tag::Sniff, LoadState::Sniff { child, .. }) => *child,
            (Tag::JoinLeaf(start), LoadState::Join(j)) => match j.leaves.get(&start) {
                Some((a, _)) => *a,
                None => {
                    core.unhold(body.len());
                    return Progress::Pending;
                }
            },
            (Tag::Inter(start, depth), LoadState::Join(j)) => match j.tree.address_of(start, depth)
            {
                Some((a, _)) => a,
                None => {
                    core.unhold(body.len());
                    return Progress::Pending;
                }
            },
            _ => {
                core.unhold(body.len());
                return Progress::Pending;
            }
        };
        core.hash(
            tag,
            Work::Chunk {
                address,
                wire: body,
            },
        );
        Progress::Pending
    }

    fn hashed(&mut self, core: &mut Core, tag: Tag, verdict: Verdict, work: Work) -> Progress {
        let (Verdict::Chunk(result), Work::Chunk { address, wire }) = (verdict, work) else {
            return Progress::Failed(Failure::Unverifiable);
        };
        if let Err(r) = result {
            core.unhold(wire.len());
            return Progress::Failed(refusal(r));
        }
        match tag {
            Tag::NodeRoot => {
                core.unhold(wire.len());
                self.rooted(core, wire)
            }
            Tag::Sniff => {
                let LoadState::Sniff { depth, .. } = self.state else {
                    core.unhold(wire.len());
                    return Progress::Pending;
                };
                // Kept for the join, which reads the same chunks.
                self.known.push((address, wire.clone()));
                self.state = LoadState::Root;
                self.sniff_from(core, wire, depth + 1)
            }
            Tag::JoinLeaf(start) => {
                core.unhold(wire.len());
                let LoadState::Join(join) = &mut self.state else {
                    return Progress::Pending;
                };
                let Some((_, len)) = join.leaves.remove(&start) else {
                    return Progress::Pending;
                };
                if let Err(f) = Self::place(join, start, len, &wire) {
                    return Progress::Failed(f);
                }
                self.pump(core)
            }
            Tag::Inter(start, depth) => {
                core.unhold(wire.len());
                let LoadState::Join(join) = &mut self.state else {
                    return Progress::Pending;
                };
                join.tree.settle(core, start, depth, Ok(&wire));
                self.pump(core)
            }
            _ => {
                core.unhold(wire.len());
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
    bytes: Vec<u8>,
    state: LeafState,
}

#[derive(Debug)]
struct ByteStream {
    id: PieceId,
    /// The file offset of the stream's next byte.
    pos: u64,
    stash: VecDeque<Vec<u8>>,
    /// How much of the stash's first frame is used.
    front_at: usize,
    headed: bool,
    /// Still open: not ended, failed or cancelled.
    open: bool,
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
    known: Vec<([u8; 32], Vec<u8>)>,
}

impl Body {
    fn held(&self) -> usize {
        let stash: usize = self.stream.as_ref().map_or(0, |s| {
            s.stash.iter().map(Vec::len).sum::<usize>() - s.front_at
        });
        stash
            + self
                .leaves
                .iter()
                .filter(|l| !matches!(l.state, LeafState::Hashing | LeafState::Fallback))
                .map(|l| l.bytes.len())
                .sum::<usize>()
    }

    fn stream_id(&self) -> Option<PieceId> {
        self.stream.as_ref().map(|s| s.id)
    }

    /// Moves everything on; `Err` ends the request.
    fn pump(&mut self, core: &mut Core) -> Result<(), Failure> {
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
        self.release(core)
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
                }) => self.push_leaf(address, start, len),
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
        }
        let mut headers = chunk_headers();
        headers.push(("range".to_owned(), format!("bytes={}-{}", self.fs, self.fe)));
        let id = core
            .fetch(
                Tag::Bytes,
                format!("/bytes/{}", ant::hex(&self.reference)),
                headers,
                true,
                0,
            )
            .ok_or(Failure::Unverifiable)?;
        self.stream = Some(ByteStream {
            id,
            pos: self.fs,
            stash: VecDeque::new(),
            front_at: 0,
            headed: false,
            open: true,
        });
        Ok(())
    }

    fn push_leaf(&mut self, address: [u8; 32], start: u64, len: u64) {
        // A leaf's length is at most a chunk's.
        self.leaves.push_back(Leaf {
            start,
            address,
            len: usize::try_from(len).unwrap_or(CHUNK_SIZE),
            bytes: Vec::new(),
            state: LeafState::Filling,
        });
    }

    /// Stops the stream: cancelled, and what it stashed dropped.
    fn close_stream(&mut self, core: &mut Core) {
        if let Some(s) = self.stream.as_mut() {
            if s.open {
                s.open = false;
                core.cancel_piece(s.id);
            }
            let dropped = s.stash.drain(..).map(|v| v.len()).sum::<usize>() - s.front_at;
            s.front_at = 0;
            core.unhold(dropped);
            core.consumed(s.id, dropped);
        }
    }

    /// The stash's bytes into their leaves, as the tree names them.
    fn fill(&mut self, core: &mut Core) {
        loop {
            let Some(s) = self.stream.as_mut() else {
                return;
            };
            let id = s.id;
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
                if s.front_at == front.len() {
                    s.stash.pop_front();
                    s.front_at = 0;
                }
                s.pos += n as u64;
                core.unhold(n);
                core.consumed(id, n);
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
                    }) => self.push_leaf(address, start, len),
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
            if leaf.start + leaf.bytes.len() as u64 != pos {
                // The tree's next leaf doesn't start where the stream is.
                self.stopped = Some(Failure::Unverifiable);
                continue;
            }
            let Some(front) = s.stash.front() else {
                break;
            };
            let n = (leaf.len - leaf.bytes.len()).min(front.len() - s.front_at);
            leaf.bytes
                .extend_from_slice(&front[s.front_at..s.front_at + n]);
            s.front_at += n;
            if s.front_at == front.len() {
                s.stash.pop_front();
                s.front_at = 0;
            }
            s.pos += n as u64;
            if leaf.bytes.len() == leaf.len {
                leaf.state = LeafState::Hashing;
                let bytes = std::mem::take(&mut leaf.bytes);
                core.hash(
                    Tag::Leaf(leaf.start),
                    Work::Leaf {
                        address: leaf.address,
                        len: leaf.len,
                        bytes,
                    },
                );
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
            fetch_chunk(core, Tag::Fallback(leaf.start), &leaf.address)
                .ok_or(Failure::Unverifiable)?;
            leaf.state = LeafState::Fallback;
        }
        Ok(())
    }

    /// Releases the passed leaves in order, trimmed to the body; the first
    /// that failed, or the point the stream stopped at, ends the request.
    fn release(&mut self, core: &mut Core) -> Result<(), Failure> {
        let from = self.stream_id();
        while let Some(front) = self.leaves.front() {
            match front.state {
                LeafState::Passed => {}
                LeafState::Failed(f) => return Err(f),
                LeafState::Filling => {
                    return match self.stopped.or_else(|| self.starved()) {
                        Some(f) => Err(f),
                        None => Ok(()),
                    };
                }
                _ => return Ok(()),
            }
            let Some(mut leaf) = self.leaves.pop_front() else {
                break;
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
            let mut kept = std::mem::take(&mut leaf.bytes);
            let dropped = kept.len() - (keep_to - keep_from);
            kept.truncate(keep_to);
            if keep_from > 0 {
                kept.drain(..keep_from);
            }
            core.unhold(dropped);
            if let Some(id) = from {
                core.consumed(id, dropped);
            }
            self.released = end;
            core.body(kept, from);
        }
        if self.released > self.b {
            self.close_stream(core);
            core.finish();
            return Ok(());
        }
        if let Some(f) = self.stopped.or_else(|| self.starved()) {
            return Err(f);
        }
        if self.tree_done && self.leaves.is_empty() {
            // The tree ended before the body did: its geometry doesn't
            // cover the size its root declares.
            return Err(Failure::Unverifiable);
        }
        Ok(())
    }

    fn release_all(&mut self, core: &mut Core) {
        core.unhold(self.held());
        for (_, w) in self.known.drain(..) {
            core.unhold(w.len());
        }
        self.leaves.clear();
        self.close_stream(core);
        self.tree.release(core);
    }

    fn whole(
        &mut self,
        core: &mut Core,
        tag: Tag,
        status: u16,
        body: Vec<u8>,
    ) -> Result<(), Failure> {
        match tag {
            Tag::Inter(start, depth) => {
                let Some((address, _)) = self.tree.address_of(start, depth) else {
                    core.unhold(body.len());
                    return Ok(());
                };
                if status == 200 {
                    core.hash(
                        tag,
                        Work::Chunk {
                            address,
                            wire: body,
                        },
                    );
                } else {
                    core.unhold(body.len());
                    self.tree
                        .settle(core, start, depth, Err(Failure::Status(status)));
                }
            }
            Tag::Fallback(start) => {
                let Some(leaf) = self.leaves.iter_mut().find(|l| l.start == start) else {
                    core.unhold(body.len());
                    return Ok(());
                };
                if status == 200 {
                    let bytes = std::mem::take(&mut leaf.bytes);
                    core.hash(
                        tag,
                        Work::LeafChunk {
                            address: leaf.address,
                            len: leaf.len,
                            bytes,
                            wire: body,
                        },
                    );
                } else {
                    core.unhold(body.len());
                    leaf.state = LeafState::Failed(Failure::Status(status));
                }
            }
            _ => core.unhold(body.len()),
        }
        self.pump(core)
    }

    fn failed(&mut self, core: &mut Core, tag: Tag, failure: PieceFailure) -> Result<(), Failure> {
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
    ) -> Result<(), Failure> {
        let expected = format!("bytes {}-{}/{}", self.fs, self.fe, self.total);
        let Some(s) = self.stream.as_mut() else {
            return Ok(());
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

    fn stream_data(&mut self, core: &mut Core, bytes: Vec<u8>) -> Result<(), Failure> {
        match self.stream.as_mut() {
            Some(s) if s.open && s.headed => s.stash.push_back(bytes),
            Some(s) => {
                core.unhold(bytes.len());
                core.consumed(s.id, bytes.len());
            }
            None => core.unhold(bytes.len()),
        }
        self.pump(core)
    }

    fn stream_end(&mut self, core: &mut Core) -> Result<(), Failure> {
        self.stream_stopped(Failure::Stopped);
        self.pump(core)
    }

    fn hashed(
        &mut self,
        core: &mut Core,
        tag: Tag,
        verdict: Verdict,
        work: Work,
    ) -> Result<(), Failure> {
        match (tag, verdict, work) {
            (Tag::Inter(start, depth), Verdict::Chunk(r), Work::Chunk { wire, .. }) => {
                core.unhold(wire.len());
                self.tree.settle(
                    core,
                    start,
                    depth,
                    r.map(|()| wire.as_slice()).map_err(refusal),
                );
            }
            (Tag::Leaf(start), Verdict::Leaf(matched), Work::Leaf { bytes, .. }) => {
                if let Some(leaf) = self.leaves.iter_mut().find(|l| l.start == start) {
                    leaf.bytes = bytes;
                    leaf.state = if matched {
                        LeafState::Passed
                    } else {
                        LeafState::NeedsFallback
                    };
                } else {
                    core.unhold(bytes.len());
                }
            }
            (Tag::Fallback(start), Verdict::LeafChunk(r), Work::LeafChunk { bytes, wire, .. }) => {
                core.unhold(wire.len());
                if let Some(leaf) = self.leaves.iter_mut().find(|l| l.start == start) {
                    leaf.bytes = bytes;
                    leaf.state = match r {
                        Ok(()) => LeafState::Passed,
                        Err(r) => LeafState::Failed(refusal(r)),
                    };
                } else {
                    core.unhold(bytes.len());
                }
            }
            (_, _, work) => core.unhold(work.size()),
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
    /// A manifest node the lookup asked for.
    Child(Box<Lookup>),
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
        entry: Entry,
    },
    Body(Box<Body>),
    Done,
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
    url_root: Option<Vec<u8>>,
    /// The feed the walk crossed.
    feed: Option<Feed>,
    /// A raw root's chunks the sniff checked, for its body.
    known: Vec<([u8; 32], Vec<u8>)>,
    stage: Stage,
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

    fn end(&mut self, core: &mut Core, failure: Failure) {
        self.drop_stage(core);
        core.fail(failure);
    }

    fn drop_stage(&mut self, core: &mut Core) {
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::Load { mut load, .. } => load.release(core),
            Stage::Body(mut body) => body.release_all(core),
            _ => {}
        }
    }

    /// A proven answer with a fixed body: a 404, a 308 or a 416.
    fn answer(
        &mut self,
        core: &mut Core,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        content: ContentTrust,
    ) {
        self.drop_stage(core);
        self.release_url_root(core);
        // Room for the body before the head promises it.
        if !core.fits(body.len()) {
            return core.fail(Failure::Unverifiable);
        }
        core.head(status, headers, content);
        core.hold(body.len());
        core.body(body, None);
        core.finish();
    }

    fn release_url_root(&mut self, core: &mut Core) {
        if let Some(w) = self.url_root.take() {
            core.unhold(w.len());
        }
        for (_, w) in self.known.drain(..) {
            core.unhold(w.len());
        }
    }

    fn not_found(&mut self, core: &mut Core, kind: NotFound, content: ContentTrust) {
        let (h, body) = ant::not_found(kind);
        self.answer(core, 404, h, body, content);
    }

    /// Ant's fallback for a node that isn't a manifest: a bare request gets
    /// the URL reference's own bytes; any path below it, a 404.
    fn raw_fallback(&mut self, core: &mut Core) {
        if !self.bare() {
            let label = self.label();
            return self.not_found(core, NotFound::Path, label);
        }
        self.drop_stage(core);
        let Some(wire) = self.url_root.take() else {
            return self.end(core, Failure::Unverifiable);
        };
        let entry = Entry {
            content_type: None,
            filename: ant::filename_from_path(&self.path),
            reference: self.root,
            feed: None,
        };
        // Those bytes are the URL reference's own: verified.
        self.feed = None;
        self.file_rooted(core, entry, wire);
    }

    fn loaded(&mut self, core: &mut Core, then: Then, loaded: Loaded, root_wire: Option<Vec<u8>>) {
        match then {
            Then::Root => {
                if let Some(w) = root_wire {
                    self.url_root = Some(w);
                }
                match loaded {
                    Loaded::NotAManifest => {
                        let Some(wire) = self.url_root.take() else {
                            return self.end(core, Failure::Unverifiable);
                        };
                        if !self.bare() {
                            core.unhold(wire.len());
                            return self.not_found(core, NotFound::Path, ContentTrust::Verified);
                        }
                        let entry = Entry {
                            content_type: None,
                            filename: ant::filename_from_path(&self.path),
                            reference: self.root,
                            feed: None,
                        };
                        self.file_rooted(core, entry, wire);
                    }
                    Loaded::TooLarge => self.end(core, Failure::Unverifiable),
                    Loaded::Node(bytes) => self.root_node(core, bytes),
                }
            }
            Then::Target => {
                if let Some(w) = root_wire {
                    core.unhold(w.len());
                }
                match loaded {
                    Loaded::NotAManifest => self.raw_fallback(core),
                    Loaded::TooLarge => self.end(core, Failure::Unverifiable),
                    Loaded::Node(bytes) => {
                        core.unhold(bytes.len());
                        match manifest::parse_node(&bytes) {
                            Ok(node) => {
                                let (lookup, step) = Lookup::new(node, &self.path);
                                self.step(core, Box::new(lookup), step);
                            }
                            Err(NodeError::NotAManifest) => self.raw_fallback(core),
                            Err(NodeError::Malformed) => {
                                let label = self.label();
                                self.not_found(core, NotFound::Plain, label);
                            }
                            Err(NodeError::TooLarge) => self.end(core, Failure::Unverifiable),
                        }
                    }
                }
            }
            Then::Child(mut lookup) => {
                if let Some(w) = root_wire {
                    core.unhold(w.len());
                }
                let step = match loaded {
                    Loaded::NotAManifest => lookup.refused(NodeError::NotAManifest),
                    Loaded::TooLarge => return self.end(core, Failure::Unverifiable),
                    Loaded::Node(bytes) => {
                        core.unhold(bytes.len());
                        lookup.node(&bytes)
                    }
                };
                self.step(core, lookup, step);
            }
        }
    }

    /// The URL root's node: a feed, or the manifest to look the path up in.
    fn root_node(&mut self, core: &mut Core, bytes: Vec<u8>) {
        core.unhold(bytes.len());
        let node = match manifest::parse_node(&bytes) {
            Ok(n) => n,
            Err(NodeError::NotAManifest) => {
                return self.loaded(core, Then::Root, Loaded::NotAManifest, None);
            }
            Err(NodeError::Malformed) => {
                return self.not_found(core, NotFound::Plain, ContentTrust::Verified);
            }
            Err(NodeError::TooLarge) => return self.end(core, Failure::Unverifiable),
        };
        let slash = node
            .forks
            .iter()
            .find(|f| f.byte == b'/')
            .map(|f| f.metadata.clone())
            .unwrap_or_default();
        match feed_of(&slash) {
            Ok(Some((owner, topic))) => {
                let mut headers = chunk_headers();
                headers.push(("swarm-only-root-chunk".to_owned(), "true".to_owned()));
                let path = format!("/feeds/{}/{}", ant::hex(&owner), ant::hex(&topic));
                if core
                    .fetch(Tag::Feed, path, headers, false, super::MAX_WHOLE)
                    .is_none()
                {
                    return self.end(core, Failure::Unverifiable);
                }
                self.stage = Stage::FeedIndex { owner, topic };
            }
            Ok(None) => {
                let (lookup, step) = Lookup::new(node, &self.path);
                self.step(core, Box::new(lookup), step);
            }
            // Feed metadata Ant refuses: its lookup error is a bare 404.
            Err(()) => self.not_found(core, NotFound::Plain, ContentTrust::Verified),
        }
    }

    fn step(&mut self, core: &mut Core, lookup: Box<Lookup>, step: Step) {
        let label = self.label();
        match step {
            Step::Need(reference) => {
                let Ok(address) = <[u8; 32]>::try_from(reference.as_slice()) else {
                    // A 64-byte reference: an encrypted node.
                    return self.end(core, Failure::Unverifiable);
                };
                match Load::start(core, address) {
                    Ok(load) => {
                        self.stage = Stage::Load {
                            load,
                            then: Then::Child(lookup),
                        }
                    }
                    Err(f) => self.end(core, f),
                }
            }
            Step::Done(Outcome::Found { data_ref, metadata }) => {
                let Ok(reference) = <[u8; 32]>::try_from(data_ref.as_slice()) else {
                    return self.end(core, Failure::Unverifiable);
                };
                self.release_url_root(core);
                let entry = Entry {
                    content_type: metadata.get(manifest::CONTENT_TYPE).map(str::to_owned),
                    filename: metadata
                        .get(manifest::FILENAME)
                        .map(str::to_owned)
                        .or_else(|| ant::filename_from_path(&self.path)),
                    reference,
                    feed: self.feed,
                };
                if fetch_chunk(core, Tag::FileRoot, &reference).is_none() {
                    return self.end(core, Failure::Unverifiable);
                }
                self.stage = Stage::FileRoot { entry };
            }
            Step::Done(Outcome::NotFound { root }) => {
                let kind = if root { NotFound::Root } else { NotFound::Path };
                self.not_found(core, kind, label);
            }
            Step::Done(Outcome::Directory) => {
                let (h, body) =
                    ant::redirect(&self.root_text, &self.path, &self.query, core.head_only);
                self.answer(core, 308, h, body, label);
            }
            Step::Failed(NodeError::NotAManifest) => self.raw_fallback(core),
            Step::Failed(NodeError::Malformed) => self.not_found(core, NotFound::Plain, label),
            Step::Failed(NodeError::TooLarge) | Step::TooManyNodes => {
                self.end(core, Failure::Unverifiable);
            }
        }
    }

    /// The file's root chunk passed: the head, then the body.
    fn file_rooted(&mut self, core: &mut Core, entry: Entry, wire: Vec<u8>) {
        let mut known = std::mem::take(&mut self.known);
        self.release_url_root(core);
        self.file_body(core, entry, wire, &mut known);
        for (_, w) in known {
            core.unhold(w.len());
        }
    }

    /// The head, then the body; a raw root's sniffed chunks go to it.
    fn file_body(
        &mut self,
        core: &mut Core,
        entry: Entry,
        wire: Vec<u8>,
        known: &mut Vec<([u8; 32], Vec<u8>)>,
    ) {
        let Some(chunk) = chunk_view(&wire) else {
            core.unhold(wire.len());
            return self.end(core, Failure::VerificationFailed);
        };
        // Ant's size: the span with its top byte masked.
        let mut masked = chunk.span;
        masked[SPAN_SIZE - 1] = 0;
        let total = u64::from_le_bytes(masked);
        let (_, logical) = tree::decode_span(&chunk.span);
        let content = if entry.feed.is_some() {
            ContentTrust::LatestAsserted
        } else {
            ContentTrust::Verified
        };
        let leaf = tree::is_leaf(logical);
        if logical != total
            || (leaf && chunk.payload.len() < usize::try_from(total).unwrap_or(usize::MAX))
        {
            // A span Ant reads otherwise than its joiner, or a single-chunk
            // file shorter than its span.
            core.unhold(wire.len());
            return self.end(core, Failure::Unverifiable);
        }
        let ranges = if core.head_only {
            Ranges::Full
        } else {
            ant::parse_ranges(self.range.as_deref(), total)
        };
        let (a, b) = match ranges {
            Ranges::Invalid | Ranges::NoOverlap => {
                core.unhold(wire.len());
                let t = (ranges == Ranges::NoOverlap).then_some(total);
                let (h, body) = ant::not_satisfiable(t, entry.filename.as_deref());
                return self.answer(core, 416, h, body.to_vec(), content);
            }
            Ranges::Single { start, length: 0 } => {
                core.unhold(wire.len());
                core.head(206, ant::zero_length(&entry, total, start), content);
                core.finish();
                self.stage = Stage::Done;
                return;
            }
            Ranges::Single { start, length } => {
                core.head(
                    206,
                    ant::partial(&entry, total, start, start + length - 1),
                    content,
                );
                (start, start + length - 1)
            }
            Ranges::Full | Ranges::Multi => {
                core.head(200, ant::whole(&entry, total, core.head_only), content);
                if total == 0 {
                    core.unhold(wire.len());
                    core.finish();
                    self.stage = Stage::Done;
                    return;
                }
                (0, total - 1)
            }
        };
        if core.ended() {
            // A HEAD: nothing past the file's root is read.
            core.unhold(wire.len());
            self.stage = Stage::Done;
            return;
        }
        if leaf {
            let s = usize::try_from(a).unwrap_or(0);
            let e = usize::try_from(b).unwrap_or(0) + 1;
            let bytes = chunk.payload[s..e].to_vec();
            core.unhold(wire.len() - bytes.len());
            core.body(bytes, None);
            core.finish();
            self.stage = Stage::Done;
            return;
        }
        let block = CHUNK_SIZE as u64;
        let fs = a / block * block;
        let fe = ((b / block + 1) * block).min(total) - 1;
        let (level, _) = tree::decode_span(&chunk.span);
        let branching = if level == 0 {
            tree::MAX_REFS
        } else {
            tree::max_shards(level)
        } as u64;
        let tree = Tree::new(core, &wire, total, a, b + 1, 2 * branching * block);
        core.unhold(wire.len());
        let tree = match tree {
            Ok(t) => t,
            Err(f) => return self.end(core, f),
        };
        let mut body = Box::new(Body {
            reference: entry.reference,
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
            known: std::mem::take(known),
        });
        let r = body.pump(core);
        self.stage = Stage::Body(body);
        if let Err(f) = r {
            self.end(core, f);
        }
    }

    // Events, from the machine.

    pub(crate) fn whole(
        &mut self,
        core: &mut Core,
        tag: Tag,
        status: u16,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) {
        match &mut self.stage {
            Stage::Load { load, .. } => {
                let p = load.whole(core, tag, status, body);
                self.progress(core, p);
            }
            Stage::FeedIndex { owner, topic } if tag == Tag::Feed => {
                core.unhold(body.len());
                if let Err(f) = ok_status(status) {
                    return self.end(core, f);
                }
                let index = header(headers, "swarm-feed-index").and_then(feed_index);
                let Some(index) = index else {
                    return self.end(core, Failure::VerificationFailed);
                };
                let (owner, topic) = (*owner, *topic);
                let address = fc_swarm::verify::feed_update_address(&owner, &topic, index);
                if fetch_chunk(core, Tag::Update, &address).is_none() {
                    return self.end(core, Failure::Unverifiable);
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
                if let Err(f) = ok_status(status) {
                    core.unhold(body.len());
                    return self.end(core, f);
                }
                let work = Work::FeedUpdate {
                    owner: *owner,
                    topic: *topic,
                    index: *index,
                    wire: body,
                };
                core.hash(tag, work);
            }
            Stage::FileRoot { .. } if tag == Tag::FileRoot => {
                if let Err(f) = ok_status(status) {
                    core.unhold(body.len());
                    return self.end(core, f);
                }
                let Stage::FileRoot { entry } = &self.stage else {
                    return;
                };
                let address = entry.reference;
                core.hash(
                    tag,
                    Work::Chunk {
                        address,
                        wire: body,
                    },
                );
            }
            Stage::Body(b) => {
                let r = b.whole(core, tag, status, body);
                self.body_result(core, r);
            }
            _ => core.unhold(body.len()),
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

    pub(crate) fn stream_data(&mut self, core: &mut Core, tag: Tag, id: PieceId, bytes: Vec<u8>) {
        if let (Stage::Body(b), Tag::Bytes) = (&mut self.stage, tag) {
            let r = b.stream_data(core, bytes);
            self.body_result(core, r);
        } else {
            core.unhold(bytes.len());
            core.consumed(id, bytes.len());
        }
    }

    pub(crate) fn stream_end(&mut self, core: &mut Core, tag: Tag, _id: PieceId) {
        if let (Stage::Body(b), Tag::Bytes) = (&mut self.stage, tag) {
            let r = b.stream_end(core);
            self.body_result(core, r);
        }
    }

    pub(crate) fn hashed(&mut self, core: &mut Core, tag: Tag, verdict: Verdict, work: Work) {
        match &mut self.stage {
            Stage::Load { load, .. } => {
                let p = load.hashed(core, tag, verdict, work);
                self.progress(core, p);
            }
            Stage::FeedUpdate { index, .. } if tag == Tag::Update => {
                let index = *index;
                let (Verdict::FeedUpdate(result), Work::FeedUpdate { wire, .. }) = (verdict, work)
                else {
                    return self.end(core, Failure::Unverifiable);
                };
                match result {
                    Err(r) => {
                        core.unhold(wire.len());
                        self.end(core, refusal(r));
                    }
                    Ok(FeedUpdate::V1 { reference, .. }) => {
                        core.unhold(wire.len());
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
                        // checked against its address with the signature.
                        let wrapped = wire.get(32 + 65..).map(<[u8]>::to_vec).unwrap_or_default();
                        core.unhold(wire.len());
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
                let (Verdict::Chunk(result), Work::Chunk { wire, .. }) = (verdict, work) else {
                    return self.end(core, Failure::Unverifiable);
                };
                if let Err(r) = result {
                    core.unhold(wire.len());
                    return self.end(core, refusal(r));
                }
                let Stage::FileRoot { entry } = std::mem::replace(&mut self.stage, Stage::Done)
                else {
                    return;
                };
                self.file_rooted(core, entry, wire);
            }
            Stage::Body(b) => {
                let r = b.hashed(core, tag, verdict, work);
                self.body_result(core, r);
            }
            _ => core.unhold(work.size()),
        }
    }

    fn body_result(&mut self, core: &mut Core, r: Result<(), Failure>) {
        if let Err(f) = r {
            self.end(core, f);
        } else if core.ended() {
            self.drop_stage(core);
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
                    return;
                };
                // The root chunk and a node's bytes go to the caller, held;
                // the rest is dropped.
                let root = load.root.take();
                let known = std::mem::take(&mut load.known);
                load.release(core);
                if matches!((&then, &loaded), (Then::Root, Loaded::NotAManifest)) {
                    self.known = known;
                } else {
                    for (_, w) in known {
                        core.unhold(w.len());
                    }
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

fn feed_of(meta: &manifest::Metadata) -> Result<Option<FeedKey>, ()> {
    let Some(owner) = meta.get(manifest::FEED_OWNER) else {
        return Ok(None);
    };
    let topic = meta.get(manifest::FEED_TOPIC).ok_or(())?;
    match meta.get(manifest::FEED_TYPE) {
        None | Some("Sequence" | "sequence") => {}
        Some(_) => return Err(()),
    }
    let owner = hex_bytes(owner.trim_start_matches("0x")).ok_or(())?;
    let topic = hex_bytes(topic.trim_start_matches("0x")).ok_or(())?;
    Ok(Some((
        owner.try_into().map_err(|_| ())?,
        topic.try_into().map_err(|_| ())?,
    )))
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

/// `swarm-feed-index`: the update's index as 16 hex digits.
fn feed_index(value: &str) -> Option<u64> {
    if value.len() != 16 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(value, 16).ok()
}
