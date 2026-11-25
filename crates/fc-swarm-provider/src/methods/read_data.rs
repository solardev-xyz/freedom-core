//! `readData` (swarm-provider-ipc.js's `handleReadData`; chunk-service.js's
//! `readDataRoot` and `readData`), through 0009's verified walk (deviation
//! `read-data-verified`).
//!
//! **The reference's steps, kept:** the params; one request charged; the
//! reachability check; the root chunk, checked against the reference and
//! its wire bytes charged whatever happens next; a size past the site's
//! `maxBytes` refused `data_too_large`, then the root's charge refusal; the
//! rest of the size reserved before any more is read; a blob of at most
//! 4,096 bytes is the root's payload, held to its size.
//!
//! **The walk,** where the reference has the node join `GET /bytes`
//! unranged and takes it on its length: the root's tree as `fc_swarm::tree`
//! reads it (each child's logical length from its parent's geometry, the
//! padding and the parities left out), its intermediate chunks fetched as
//! `chunk` calls with their occurrence (`tree: { length, depth }`), at most
//! eight at once; then the leaves as one ranged `bytes` stream of exactly
//! the size, each leaf checked against the address its verified parent
//! names on the hashing pool; a leaf that fails is fetched once as its own
//! chunk, which must be at its address and hold the streamed bytes. Bad
//! data, more than 2,562 data children, and an intermediate chunk at 0009's
//! eighth level are `chunk_type_mismatch`.
//!
//! **What the walk charges the page:** what the reference charges, the
//! root's wire bytes and the rest of the size. Intermediate chunks and a
//! leaf's own chunk are the core's check, not data the page reads, so the
//! verified read leaves the budget as the reference's read does ("the same
//! results").

use std::collections::{BTreeMap, VecDeque};

use fc_json::JsString;
use fc_swarm::CHUNK_SIZE;
use fc_swarm::tree::{self, Intermediate};
use fc_swarm::verify::{self, Chunk, check_leaf_chunk, leaf_matches};

use super::chunk_reads::{begin, ready};
use super::{chunk_error, chunk_failed, mismatch};
use crate::chunks::{content_addressed, data_size, safe_number};
use crate::errors::ChunkRead;
use crate::machine::node::{ERROR_TEXT, Failed};
use crate::machine::params::{bytes32, empty_options, hex_string, require_params};
use crate::machine::{
    Abort, AskId, Cx, Event, Failure, NodeCall, Outcome, Reply, Step, World, done, fail,
};
use crate::value::{Value, encode_base64};

/// The largest read budget's `maxBytes`, `B`.
const B: u64 = 5 * 1024 * 1024;
/// The walk's data children, at most: 2 + 2⌈B / 4,096⌉, the grammar's cap
/// on a `readData` request's `chunk` calls.
pub const MAX_SLOTS: usize = 2 + 2 * (B as usize).div_ceil(CHUNK_SIZE);
/// 0009's `MAX_LEVELS`: an intermediate chunk is fetched only above it.
pub const MAX_LEVELS: u8 = 8;
/// At most this many `chunk` calls open at once.
pub const OPEN_AT_ONCE: usize = 8;

const READ: ChunkRead = ChunkRead::Data;

/// `handleReadData`.
pub(crate) struct ReadData {
    reference: JsString,
    address: [u8; 32],
    stage: Stage,
}

enum Stage {
    Ready(AskId),
    Root(AskId),
    Tree(Walk),
    Stream {
        id: AskId,
        walk: Walk,
        data: Vec<u8>,
    },
    Hashing {
        id: AskId,
        walk: Walk,
    },
    Fallbacks {
        walk: Walk,
        data: Vec<u8>,
        waiting: VecDeque<usize>,
        open: BTreeMap<AskId, usize>,
    },
    Gone,
}

impl ReadData {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, params: &Value) -> Result<Self, Outcome> {
        require_params(params)?;
        empty_options(params.get("options"))?;
        // 32 bytes only: an encrypted reference (64 bytes) is refused too.
        let reference = hex_string(
            params.get("reference"),
            32,
            "invalid_reference",
            "reference",
        )?
        .clone();
        let address = bytes32(&reference).ok_or_else(Failure::internal_error)?;
        let ready = begin(cx)?;
        Ok(ReadData {
            reference,
            address,
            stage: Stage::Ready(ready),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match std::mem::replace(&mut self.stage, Stage::Gone) {
            Stage::Ready(ready_id) if id == ready_id => {
                if let Err(step) = ready(event) {
                    return step;
                }
                self.stage = Stage::Root(cx.whole(NodeCall::chunk(&self.address)));
                Step::Wait
            }
            Stage::Root(root_id) if id == root_id => self.root(cx, event),
            Stage::Tree(mut walk) => match walk.answer(&self.reference, id, event) {
                Err(failure) => fail(failure),
                Ok(()) => self.next(cx, walk),
            },
            Stage::Stream {
                id: stream_id,
                walk,
                mut data,
            } if id == stream_id => match event {
                Event::Head(_) => {
                    self.stage = Stage::Stream {
                        id: stream_id,
                        walk,
                        data,
                    };
                    Step::Wait
                }
                Event::Data(bytes) => {
                    data.extend_from_slice(&bytes);
                    cx.credit(stream_id, bytes.len());
                    self.stage = Stage::Stream {
                        id: stream_id,
                        walk,
                        data,
                    };
                    Step::Wait
                }
                Event::End => {
                    if data.len() as u64 != walk.size {
                        return fail(short(data.len(), walk.size));
                    }
                    let job = Job {
                        leaves: walk
                            .leaves
                            .iter()
                            .map(|l| (l.start, l.length, l.address))
                            .collect(),
                        data,
                    };
                    let hash_id = cx.hash(job);
                    self.stage = Stage::Hashing { id: hash_id, walk };
                    Step::Wait
                }
                Event::Abort(Abort::TooLarge) | Event::Failed(Failed::TooLarge) => {
                    fail(longer(walk.size))
                }
                Event::Abort(_) => fail(Failure::internal(ERROR_TEXT)),
                Event::Reply(reply) => fail(chunk_error(READ, self.reference.as_str(), &reply)),
                Event::Failed(failed) => fail(chunk_failed(failed, READ)),
                _ => fail(Failure::internal_error()),
            },
            Stage::Hashing { id: hash_id, walk } if id == hash_id => {
                let Event::Hashed(JobDone { data, failed }) = event else {
                    return fail(Failure::internal_error());
                };
                if failed.is_empty() {
                    return done(result(&data));
                }
                let mut stage = Stage::Fallbacks {
                    walk,
                    data,
                    waiting: failed.into_iter().collect(),
                    open: BTreeMap::new(),
                };
                fill_fallbacks(cx, &mut stage);
                self.stage = stage;
                Step::Wait
            }
            Stage::Fallbacks {
                walk,
                data,
                waiting,
                mut open,
            } => {
                let Some(leaf_index) = open.remove(&id) else {
                    return fail(Failure::internal_error());
                };
                let leaf = walk.leaves[leaf_index];
                let reply = match event {
                    Event::Reply(reply) => reply,
                    Event::Failed(failed) => return fail(chunk_failed(failed, READ)),
                    _ => return fail(Failure::internal_error()),
                };
                if !reply.ok() {
                    return fail(chunk_error(READ, self.reference.as_str(), &reply));
                }
                let streamed = &data[leaf.start..leaf.start + leaf.length];
                if check_leaf_chunk(&leaf.address, leaf.length, streamed, &reply.body).is_err() {
                    return fail(mismatch(READ));
                }
                if waiting.is_empty() && open.is_empty() {
                    return done(result(&data));
                }
                let mut stage = Stage::Fallbacks {
                    walk,
                    data,
                    waiting,
                    open,
                };
                fill_fallbacks(cx, &mut stage);
                self.stage = stage;
                Step::Wait
            }
            _ => fail(Failure::internal_error()),
        }
    }

    /// The root chunk's answer: `readDataRoot` and the budget's steps.
    fn root<W: World>(&mut self, cx: &mut Cx<'_, W>, event: Event) -> Step {
        let reply = match event {
            Event::Reply(reply) => reply,
            Event::Failed(failed) => return fail(chunk_failed(failed, READ)),
            _ => return fail(Failure::internal_error()),
        };
        if !reply.ok() {
            return fail(chunk_error(READ, self.reference.as_str(), &reply));
        }
        let Some(cac) = content_addressed(&self.address, &reply.body) else {
            return fail(mismatch(READ));
        };
        let size = data_size(&cac.span);
        let chunk_bytes = reply.body.len() as u64;
        // The root came off the network: charged before any refusal.
        let charged = cx.consume(0, chunk_bytes);
        let max = cx.max_bytes();
        if size > max {
            return fail(Failure::invalid_params_with(
                format!("Data exceeds the maximum read size of {max} bytes"),
                "data_too_large",
                vec![("limit", Value::int(max)), ("actual", safe_number(size))],
            ));
        }
        if let Err(refused) = charged {
            return fail(refused);
        }
        if size > chunk_bytes
            && let Err(refused) = cx.reserve(size - chunk_bytes)
        {
            return fail(refused);
        }
        // `size` is at most the larger budget's 5 MiB from here.
        let Ok(n) = usize::try_from(size) else {
            return fail(Failure::internal_error());
        };
        if n <= CHUNK_SIZE {
            let data = &cac.payload[..cac.payload.len().min(n)];
            if data.len() != n {
                return fail(short(data.len(), size));
            }
            return done(result(data));
        }
        let chunk = Chunk {
            span: cac.span,
            payload: cac.payload,
        };
        match Walk::new(&self.address, &chunk, size) {
            Ok(walk) => self.next(cx, walk),
            Err(()) => fail(mismatch(READ)),
        }
    }

    /// Fetches what the tree still needs, or, once it has every
    /// intermediate chunk, streams the leaves.
    fn next<W: World>(&mut self, cx: &mut Cx<'_, W>, mut walk: Walk) -> Step {
        walk.fetch(cx);
        if !walk.loaded() {
            self.stage = Stage::Tree(walk);
            return Step::Wait;
        }
        walk.order();
        let size = walk.size;
        let Ok(n) = usize::try_from(size) else {
            return fail(Failure::internal_error());
        };
        let call = NodeCall::bytes(&self.address, Some((0, size - 1)), n);
        let id = cx.stream(call, size);
        self.stage = Stage::Stream {
            id,
            walk,
            data: Vec::with_capacity(n),
        };
        Step::Wait
    }
}

fn fill_fallbacks<W: World>(cx: &mut Cx<'_, W>, stage: &mut Stage) {
    let Stage::Fallbacks {
        walk,
        waiting,
        open,
        ..
    } = stage
    else {
        return;
    };
    while open.len() < OPEN_AT_ONCE {
        let Some(index) = waiting.pop_front() else {
            break;
        };
        let leaf = walk.leaves[index];
        let call = NodeCall::chunk(&leaf.address).with_tree(leaf.length as u64, leaf.depth);
        open.insert(cx.whole(call), index);
    }
}

/// The reference's text for a blob shorter than its size.
fn short(got: usize, size: u64) -> Failure {
    Failure::internal(format!("Node returned {got} bytes for a {size}-byte blob"))
}

/// A blob past its size, which main stopped at `max_bytes`.
fn longer(size: u64) -> Failure {
    Failure::internal(format!(
        "Node returned more than {size} bytes for a {size}-byte blob"
    ))
}

fn result(data: &[u8]) -> Value {
    Value::object([
        ("data", Value::String(encode_base64(data).into())),
        ("encoding", Value::str("base64")),
    ])
}

/// A leaf of the tree: where it starts, its logical length, its depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Leaf {
    address: [u8; 32],
    start: usize,
    length: usize,
    depth: u8,
}

/// An intermediate chunk's place in the tree, and its children once main
/// returned it.
#[derive(Debug)]
struct Node {
    address: [u8; 32],
    length: u64,
    depth: u8,
    children: Vec<Child>,
}

#[derive(Debug, Clone, Copy)]
enum Child {
    Leaf {
        address: [u8; 32],
        length: u64,
        depth: u8,
    },
    Inner(usize),
}

/// The file's tree as the walk reads it.
#[derive(Debug)]
struct Walk {
    size: u64,
    /// The root at 0, then each intermediate occurrence.
    nodes: Vec<Node>,
    waiting: VecDeque<usize>,
    open: BTreeMap<AskId, usize>,
    /// Data children of positive length taken into the tree.
    slots: usize,
    leaves: Vec<Leaf>,
}

impl Walk {
    fn new(address: &[u8; 32], root: &Chunk<'_>, size: u64) -> Result<Walk, ()> {
        let mut walk = Walk {
            size,
            nodes: vec![Node {
                address: *address,
                length: size,
                depth: 0,
                children: Vec::new(),
            }],
            waiting: VecDeque::new(),
            open: BTreeMap::new(),
            slots: 0,
            leaves: Vec::new(),
        };
        walk.take(0, root)?;
        Ok(walk)
    }

    /// Reads node `index`'s chunk as an intermediate of its length, and
    /// takes its data children into the tree, one level deeper.
    fn take(&mut self, index: usize, chunk: &Chunk<'_>) -> Result<(), ()> {
        let (length, depth) = (self.nodes[index].length, self.nodes[index].depth);
        let node: Intermediate<'_> = tree::intermediate(chunk, length).map_err(|_| ())?;
        let mut children = Vec::with_capacity(node.len());
        for i in 0..node.len() {
            let Some((address, length)) = node.child(i) else {
                return Err(());
            };
            if length == 0 {
                continue;
            }
            self.slots += 1;
            if self.slots > MAX_SLOTS {
                return Err(());
            }
            let depth = depth + 1;
            if tree::is_leaf(length) {
                children.push(Child::Leaf {
                    address,
                    length,
                    depth,
                });
                continue;
            }
            if depth >= MAX_LEVELS {
                return Err(());
            }
            self.nodes.push(Node {
                address,
                length,
                depth,
                children: Vec::new(),
            });
            let at = self.nodes.len() - 1;
            self.waiting.push_back(at);
            children.push(Child::Inner(at));
        }
        self.nodes[index].children = children;
        Ok(())
    }

    /// Asks for waiting intermediate chunks, up to eight open.
    fn fetch<W: World>(&mut self, cx: &mut Cx<'_, W>) {
        while self.open.len() < OPEN_AT_ONCE {
            let Some(index) = self.waiting.pop_front() else {
                break;
            };
            let node = &self.nodes[index];
            let call = NodeCall::chunk(&node.address).with_tree(node.length, node.depth);
            self.open.insert(cx.whole(call), index);
        }
    }

    fn loaded(&self) -> bool {
        self.waiting.is_empty() && self.open.is_empty()
    }

    /// An intermediate chunk's answer.
    fn answer(&mut self, reference: &JsString, id: AskId, event: Event) -> Result<(), Failure> {
        let index = self.open.remove(&id).ok_or_else(Failure::internal_error)?;
        let reply: Reply = match event {
            Event::Reply(reply) => reply,
            Event::Failed(failed) => return Err(chunk_failed(failed, READ)),
            _ => return Err(Failure::internal_error()),
        };
        if !reply.ok() {
            return Err(chunk_error(READ, reference.as_str(), &reply));
        }
        let address = self.nodes[index].address;
        let chunk =
            verify::content_addressed(&address, &reply.body).ok_or_else(|| mismatch(READ))?;
        self.take(index, &chunk).map_err(|()| mismatch(READ))
    }

    /// The leaves in the file's order, each with its start.
    fn order(&mut self) {
        let mut leaves = Vec::new();
        let mut start = 0usize;
        // Depth-first, children in order: an explicit stack of (node, next
        // child).
        let mut stack = vec![(0usize, 0usize)];
        while let Some((index, next)) = stack.pop() {
            let Some(child) = self.nodes[index].children.get(next).copied() else {
                continue;
            };
            stack.push((index, next + 1));
            match child {
                Child::Leaf {
                    address,
                    length,
                    depth,
                } => {
                    // A leaf is at most 4,096 bytes.
                    let length = length as usize;
                    leaves.push(Leaf {
                        address,
                        start,
                        length,
                        depth,
                    });
                    start += length;
                }
                Child::Inner(inner) => stack.push((inner, 0)),
            }
        }
        self.leaves = leaves;
    }
}

/// Work for 0009's hashing pool: each streamed leaf checked against the
/// address its parent names, under its logical length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    data: Vec<u8>,
    /// Each leaf's start, logical length and address.
    leaves: Vec<(usize, usize, [u8; 32])>,
}

impl Job {
    /// Runs the job: anywhere, it does no I/O.
    pub fn run(self) -> JobDone {
        let failed = self
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, (start, length, address))| {
                let streamed = self.data.get(*start..start + length).unwrap_or(&[]);
                !leaf_matches(address, *length, streamed)
            })
            .map(|(i, _)| i)
            .collect();
        JobDone {
            data: self.data,
            failed,
        }
    }
}

/// A [`Job`]'s result, which goes back to its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobDone {
    data: Vec<u8>,
    /// The leaves whose bytes didn't match, in order.
    failed: Vec<usize>,
}
