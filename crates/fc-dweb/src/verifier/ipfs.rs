//! The IPFS walk (design 0009, The IPFS walk; The CAR request; Raw blocks;
//! IPNS and DNSLink), with `GatewayCore`'s answers built from what passed
//! ([`super::gateway`]):
//!
//! 1. **An IPNS name** first: its record, checked by `fc_ipfs::ipns`, names
//!    the root (at most four records: `GatewayCore` refuses what a fourth
//!    names); the label is `latest_asserted`.
//! 2. **The path,** split on `/` and each segment decoded once
//!    (`ipfs-path-decoding`), resolved from the root one directory or HAMT
//!    shard at a time, the shards found by the name's hash
//!    (`hamt-lookup`). A missing name in a verified directory is
//!    `GatewayCore`'s 404.
//! 3. **The entity:** a file, its blocks depth-first within the range; a
//!    directory's `index.html` as a file, or else the listing (a HAMT's from
//!    every shard).
//!
//! **Where the blocks come from:** one CAR per entity
//! (`dag-scope=entity`, `entity-bytes` for a range), read as a block
//! source. Each block is hashed, then must be the block the walk needs
//! next; one that isn't ends the CAR, and the walk fetches the rest as raw
//! blocks. So does a gateway without ordered CARs, from the start.

use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};

use fc_ipfs::Refusal as BlockRefusal;
use fc_ipfs::car::{self, End};
use fc_ipfs::cid::{self as ipfs_cid, IDENTITY, SHA2_256};
use fc_ipfs::dagpb;
use fc_ipfs::hamt::{self, Step};
use fc_ipfs::unixfs::{self, Kind};

use super::gateway::{self, Cache, RangeError};
use super::jobs::{Verdict, Work};
use super::{Ask, Failure, PieceFailure, PieceId};
use crate::plan::{ContentTrust, Root};
use crate::validate::Refusal as PlanRefusal;

/// The most raw block requests open at once (0009, Raw blocks).
const MAX_RAW_PIECES: usize = 8;
/// Levels of a file's DAG (0009, Bounds).
const MAX_FILE_DEPTH: usize = 64;
/// Path segments (0009, Bounds).
const MAX_SEGMENTS: usize = 256;
/// The IPNS resolutions `GatewayCore` serves from: it makes a fourth,
/// then answers 400.
const MAX_RESOLUTIONS: usize = 3;
/// Verified body waiting for the page (queued, or sent and not yet
/// credited) at which no more stream bytes are read and no raw block is
/// asked for: the page holds the gateway back.
const QUEUE_LIMIT: usize = 512 << 10;
const CAR_ACCEPT: &str = "application/vnd.ipld.car; version=1; order=dfs; dups=y";
const RAW_ACCEPT: &str = "application/vnd.ipld.raw";
const RECORD_ACCEPT: &str = "application/vnd.ipfs.ipns-record";
/// Sections hashing or waiting their turn past which the CAR isn't read
/// further: the walk holds the gateway back.
const PENDING_LIMIT: usize = 2 << 20;
/// A CAR's reading room: one section and the header.
const CAR_ROOM: usize = car::MAX_SECTION + car::MAX_HEADER;
/// What a CAR section's hash job holds beside its bytes, until its verdict
/// is used: the job and its output, the result, and their map entries.
const SECTION_COST: usize = 512;
/// A held shard's map entry, beside its CID and block.
const MAP_ENTRY: usize = 128;

/// What a piece or a job is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tag {
    /// The IPNS record.
    Record,
    /// The CAR.
    Car,
    /// A CAR's section, by its number.
    Section(u64),
    /// A raw block, by the need it answers.
    Raw(u64),
}

type Core = super::Core<Tag>;

/// What the request asks beside its path.
#[derive(Debug, Clone)]
pub(crate) struct Asked {
    pub range: Option<String>,
    pub if_none_match: Option<String>,
    pub now: i64,
    pub car: bool,
}

fn refusal(r: BlockRefusal) -> Failure {
    match r {
        BlockRefusal::VerificationFailed => Failure::VerificationFailed,
        BlockRefusal::Unverifiable => Failure::Unverifiable,
        BlockRefusal::Malformed => Failure::Malformed,
    }
}

fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Whether a CAR's type is the one asked for: `version=1`, `order=dfs`,
/// `dups=y`, in any order.
fn car_type_ok(value: &str) -> bool {
    let mut parts = value.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|t| t.eq_ignore_ascii_case("application/vnd.ipld.car"))
    {
        return false;
    }
    let mut params: Vec<(String, String)> = parts
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase()))
        .collect();
    params.sort();
    params
        == [
            ("dups".to_owned(), "y".to_owned()),
            ("order".to_owned(), "dfs".to_owned()),
            ("version".to_owned(), "1".to_owned()),
        ]
}

/// A CID's text in a record's value: a CIDv0 in base58, or a CIDv1 in
/// base32 (either case), base58btc or base36.
fn cid_from_text(text: &str) -> Option<Vec<u8>> {
    if text.starts_with("Qm") {
        let bytes = crate::cid::base58_decode(text)?;
        return ipfs_cid::parse(&bytes).map(|c| c.bytes.to_vec());
    }
    let bytes = match text.as_bytes().first()? {
        b'b' => ipfs_cid::from_base32(text)?,
        b'B' => ipfs_cid::from_base32(&text.to_ascii_lowercase())?,
        b'z' => crate::cid::base58_decode(&text[1..])?,
        b'k' => crate::cid::base36_decode(&text[1..])?,
        _ => return None,
    };
    ipfs_cid::parse(&bytes).map(|c| c.bytes.to_vec())
}

/// A CID as `GatewayCore` shows it: a CIDv0 in base58, a CIDv1 in base32.
fn display(cid: &[u8]) -> String {
    ipfs_cid::parse(cid).map_or_else(String::new, |c| ipfs_cid::to_text(&c))
}

/// `GatewayCore`'s `is_traversal_segment`: `.` or `..`, as written or
/// with each `%XX` decoded once.
fn traversal(segment: &str) -> bool {
    if matches!(segment, "." | "..") {
        return true;
    }
    if !segment.contains('%') {
        return false;
    }
    let hex = |c: Option<&u8>| c.and_then(|&c| char::from(c).to_digit(16));
    let b = segment.as_bytes();
    let (mut out, mut n, mut i) = ([0u8; 2], 0, 0);
    while i < b.len() {
        let byte = if b[i] == b'%' {
            let (Some(h), Some(l)) = (hex(b.get(i + 1)), hex(b.get(i + 2))) else {
                return false;
            };
            i += 3;
            (h * 16 + l) as u8
        } else {
            i += 1;
            b[i - 1]
        };
        // Past two bytes it can't be `.` or `..`.
        let Some(slot) = out.get_mut(n) else {
            return false;
        };
        *slot = byte;
        n += 1;
    }
    matches!(&out[..n], b"." | b"..")
}

/// What strings hold on the heap: their bytes and the vector's slots.
#[allow(clippy::ptr_arg)]
fn strings_cost(v: &Vec<String>) -> usize {
    v.iter().map(String::capacity).sum::<usize>() + v.capacity() * std::mem::size_of::<String>()
}

/// A path's segments, each decoded once; `None` when one is refused.
fn segments(path: &str) -> Option<Vec<String>> {
    let below = path.strip_prefix('/').unwrap_or(path);
    if below.is_empty() {
        return Some(Vec::new());
    }
    fc_ipfs::path::decode_segments(below)
}

/// What the walk needs a block for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum What {
    /// The node reached after this many segments.
    Path(usize),
    /// A HAMT shard on segment `seg`'s lookup, at `level`.
    PathShard { seg: usize, level: usize },
    /// A sub-shard of the directory reached, read whole for its entries.
    EntityShard { level: usize },
    /// The directory's `index.html`, its root.
    Index,
    /// A file node below the root: its content's offset and length.
    File { start: u64, len: u64, depth: usize },
}

#[derive(Debug, Clone)]
struct Need {
    seq: u64,
    cid: Vec<u8>,
    what: What,
}

/// A raw block asked for.
#[derive(Debug)]
struct RawPiece {
    id: PieceId,
    buf: Vec<u8>,
    /// Room held for bytes yet to come.
    reserved: usize,
    /// The CID's length, held for the hash job.
    cid_len: usize,
    hashing: bool,
}

impl RawPiece {
    /// What it holds of the request's memory.
    fn held(&self) -> usize {
        self.buf.len() + self.reserved + self.cid_len
    }
}

/// A section judged: its CID, its block and the verdict.
type Judged = (Vec<u8>, Vec<u8>, Result<(), BlockRefusal>);

/// The CAR being read.
#[derive(Debug)]
struct CarStream {
    id: PieceId,
    reader: car::Reader,
    headed: bool,
    open: bool,
    /// Bytes not yet given to the reader, while the body waits for credit.
    stash: VecDeque<Vec<u8>>,
    /// Sections given to the hashing pool, in order, and those whose
    /// verdict came, waiting for the ones before them.
    sent: u64,
    done: u64,
    verdicts: BTreeMap<u64, Judged>,
    /// The bytes of sections hashing or waiting their turn.
    pending: usize,
    /// The stream has ended: the stash is all there is.
    finished: bool,
    /// The stream has ended, cleanly.
    ended: bool,
    /// The stream ended early, or failed: once the sections before it are
    /// used, the walk ends with this.
    broken: Option<Failure>,
}

/// The file being served.
#[derive(Debug)]
struct File {
    /// The body: bytes `a..=b`.
    a: u64,
    b: u64,
    len: u64,
    /// Before the head: the type is sniffed from bytes `0..=end`.
    sniff: Option<u64>,
    /// The head is out.
    headed: bool,
    /// The bytes the sniff waits for, then released.
    early: Vec<u8>,
    mime: Option<String>,
    etag: String,
    range: Option<(u64, u64)>,
}

/// Where the walk stands.
#[derive(Debug)]
enum Stage {
    /// The record of `name` asked for; `hop` resolutions so far.
    Record {
        name: String,
        hop: usize,
    },
    Dag,
    Done,
}

/// The directory reached, when it is a HAMT: its shards, for the
/// `index.html` lookup by hash, then the listing.
#[derive(Debug, Default)]
struct Hamt {
    root: Vec<u8>,
    shards: BTreeMap<Vec<u8>, Vec<u8>>,
    /// What the shards hold of the request's memory.
    held: usize,
}

/// The request's IPFS walk.
#[derive(Debug)]
pub(crate) struct Walk {
    asked: Asked,
    /// The request path below the root or name, as written.
    raw_path: String,
    /// For IPNS: the name the request asked for, and its path's segments.
    ipns: Option<String>,
    rest: Vec<String>,
    stage: Stage,
    /// The resolved root, its text as `GatewayCore` shows it, and the
    /// segments below it.
    root: Vec<u8>,
    root_text: String,
    segments: Vec<String>,
    cache: Cache,
    label: ContentTrust,
    needs: VecDeque<Need>,
    /// The needs' buffer, held: its capacity in slots.
    needs_slots: usize,
    next_seq: u64,
    /// What the path's strings hold (the request's, the records', the
    /// served path's).
    path_held: usize,
    /// Blocks checked, waiting for their turn: by need.
    arrived: BTreeMap<u64, Vec<u8>>,
    raw: BTreeMap<u64, RawPiece>,
    /// Raw blocks only, from here on.
    raw_only: bool,
    car: Option<CarStream>,
    hamt: Option<Hamt>,
    file: Option<File>,
    /// The served path's segments (the index document's, for a directory).
    served: Vec<String>,
}

impl Walk {
    pub(crate) fn start(
        core: &mut Core,
        root: &Root,
        path: &str,
        asked: Asked,
    ) -> Result<Self, PlanRefusal> {
        let raw_only = !asked.car;
        let mut walk = Self {
            asked,
            raw_path: path.strip_prefix('/').unwrap_or(path).to_owned(),
            ipns: None,
            rest: Vec::new(),
            stage: Stage::Done,
            root: Vec::new(),
            root_text: String::new(),
            segments: Vec::new(),
            cache: Cache::Immutable,
            label: ContentTrust::Verified,
            needs: VecDeque::new(),
            needs_slots: 0,
            next_seq: 0,
            path_held: 0,
            arrived: BTreeMap::new(),
            raw: BTreeMap::new(),
            raw_only,
            car: None,
            hamt: None,
            file: None,
            served: Vec::new(),
        };
        // The request's segments: their room held before they are built.
        let n = path.split('/').filter(|s| !s.is_empty()).count();
        if n > MAX_SEGMENTS || !walk.reserve_path(core, n, path.len()) {
            core.fail(Failure::Unverifiable);
            return Ok(walk);
        }
        let Some(rest) = segments(path) else {
            walk.page(core, 400, "path traversal segments are not allowed");
            return Ok(walk);
        };
        match root {
            Root::Ipfs(text) => {
                let cid = ipfs_cid::from_base32(text).ok_or(PlanRefusal::Root)?;
                walk.resolved(core, cid, rest);
            }
            Root::Ipns(name) => {
                walk.ipns = Some(name.clone());
                walk.rest = rest;
                walk.settle_path(core);
                walk.cache = Cache::Mutable;
                walk.label = ContentTrust::LatestAsserted;
                walk.ask_record(core, name.clone(), 1);
            }
            Root::Swarm(_) => return Err(PlanRefusal::Root),
        }
        Ok(walk)
    }

    /// `GatewayCore`'s page for an error the walk proves.
    fn page(&mut self, core: &mut Core, status: u16, detail: &str) {
        let (h, body) = gateway::error_page(status, detail);
        self.answer(core, status, h, body);
    }

    /// A proven answer with a fixed body.
    fn answer(
        &mut self,
        core: &mut Core,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) {
        self.stop(core);
        if !core.fits(body.len()) {
            return core.fail(Failure::Unverifiable);
        }
        core.head(status, headers, self.label);
        core.hold(body.len());
        core.body(body, None);
        core.finish();
    }

    fn end(&mut self, core: &mut Core, failure: Failure) {
        self.stop(core);
        core.fail(failure);
    }

    /// Drops every source and what it holds.
    fn stop(&mut self, core: &mut Core) {
        self.stage = Stage::Done;
        let cids: usize = self.needs.iter().map(|n| n.cid.len()).sum();
        core.unhold(cids + self.needs_slots);
        self.needs = VecDeque::new();
        self.needs_slots = 0;
        for (_, b) in std::mem::take(&mut self.arrived) {
            core.unhold(b.len());
        }
        for (_, r) in std::mem::take(&mut self.raw) {
            core.unhold(r.held());
            if !r.hashing {
                core.cancel_piece(r.id);
            }
        }
        self.close_car(core);
        if let Some(h) = self.hamt.take() {
            core.unhold(h.held);
        }
        if let Some(f) = self.file.take() {
            core.unhold(f.early.len());
        }
    }

    fn close_car(&mut self, core: &mut Core) {
        if let Some(c) = self.car.take() {
            if c.open {
                core.cancel_piece(c.id);
            }
            core.unhold(CAR_ROOM);
            core.unhold(c.stash.iter().map(Vec::len).sum());
            // Sections still hashing: their jobs' bytes come back with
            // their results, and are dropped then; their costs go now.
            let judged = c.verdicts.len() as u64;
            let hashing = c.sent.saturating_sub(c.done).saturating_sub(judged);
            core.unhold(
                usize::try_from(hashing)
                    .unwrap_or(usize::MAX)
                    .saturating_mul(SECTION_COST),
            );
            for (_, (cid, block, _)) in c.verdicts {
                core.unhold(cid.len() + block.len() + SECTION_COST);
            }
        }
    }

    // IPNS.

    fn ask_record(&mut self, core: &mut Core, name: String, hop: usize) {
        let path = format!("/ipns/{name}?format=ipns-record");
        let headers = vec![("accept".to_owned(), RECORD_ACCEPT.to_owned())];
        if core
            .fetch(
                Tag::Record,
                path,
                headers,
                Ask::Whole(fc_ipfs::ipns::MAX_RECORD),
            )
            .is_none()
        {
            return core.fail(Failure::Unverifiable);
        }
        self.stage = Stage::Record { name, hop };
    }

    fn record_value(&mut self, core: &mut Core, value: &str, hop: usize) {
        let mut parts = value.splitn(4, '/');
        let (Some(""), Some(ns), Some(target)) = (parts.next(), parts.next(), parts.next()) else {
            return self.end(core, Failure::VerificationFailed);
        };
        let below = parts.next().unwrap_or("");
        let cid = match ns {
            "ipfs" => match cid_from_text(target) {
                Some(cid) => Some(cid),
                None => return self.end(core, Failure::Unverifiable),
            },
            "ipns" => None,
            _ => return self.end(core, Failure::VerificationFailed),
        };
        // `GatewayCore` matches a value's segments as written, decoding
        // none, and refuses one that is `.` or `..`, as written or
        // percent-encoded, with its 400; a name's too (split_name_path).
        if (cid.is_none() && traversal(target)) || below.split('/').any(traversal) {
            return self.page(core, 400, "path traversal segments are not allowed");
        }
        // The value's segments ahead of the request's: at most 256 in all,
        // their room held before they are built.
        let n = below.split('/').filter(|s| !s.is_empty()).count();
        let total = n + self.rest.len();
        if total > MAX_SEGMENTS || !self.reserve_path(core, total, below.len()) {
            return self.end(core, Failure::Unverifiable);
        }
        let mut inner = Vec::with_capacity(total);
        inner.extend(
            below
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        );
        let mut old = std::mem::take(&mut self.rest);
        inner.append(&mut old);
        drop(old);
        match cid {
            Some(cid) => self.resolved(core, cid, inner),
            None => {
                // A name with a key the core verifies is followed; DNSLink,
                // or another key, can't be.
                if !matches!(
                    crate::verify::ipns_name_kind(target),
                    crate::verify::NameKind::Ed25519 | crate::verify::NameKind::Sha256
                ) {
                    return self.end(core, Failure::Unverifiable);
                }
                self.rest = inner;
                self.settle_path(core);
                self.ask_record(core, target.to_owned(), hop + 1);
            }
        }
    }

    // The DAG.

    /// The root is known: walk its path.
    fn resolved(&mut self, core: &mut Core, root: Vec<u8>, inner: Vec<String>) {
        let Some(cid) = ipfs_cid::parse(&root) else {
            return self.end(core, Failure::VerificationFailed);
        };
        if cid.hash != SHA2_256 && cid.hash != IDENTITY {
            // A hash the native node doesn't verify (blake3, say).
            return self.end(core, Failure::Unverifiable);
        }
        if cid.codec != ipfs_cid::DAG_PB && cid.codec != ipfs_cid::RAW {
            return self.end(core, Failure::Unverifiable);
        }
        self.root_text = display(&root);
        let mut inner = inner;
        inner.retain(|s| !s.is_empty());
        self.segments = inner;
        self.settle_path(core);
        self.stage = Stage::Dag;
        if !self.needs_room(core, 1, root.len()) {
            return self.end(core, Failure::Unverifiable);
        }
        self.add_need(&root, What::Path(0));
        self.root = root;
        self.pump(core);
    }

    /// Room for `n` more needs whose CIDs hold `cids` bytes, reserved
    /// before the deque grows (its new buffer beside the old one while it
    /// moves); false when the request can't hold them.
    fn needs_room(&mut self, core: &mut Core, n: usize, cids: usize) -> bool {
        let slot = std::mem::size_of::<Need>();
        let cap = self.needs.capacity();
        let want = self.needs.len().saturating_add(n);
        let grown = if want > cap {
            want.saturating_mul(slot)
        } else {
            0
        };
        if !core.fits(grown.saturating_add(cids)) {
            return false;
        }
        core.hold(grown + cids);
        if want > cap {
            self.needs.reserve_exact(n);
            let now = self.needs.capacity().saturating_mul(slot);
            // What the allocator gave past the ask; then the old buffer,
            // freed.
            core.hold(now.saturating_sub(grown));
            core.unhold(self.needs_slots);
            self.needs_slots = now;
        }
        true
    }

    /// A need at the back, its room made ([`Walk::needs_room`]).
    fn add_need(&mut self, cid: &[u8], what: What) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.needs.push_back(Need {
            seq,
            cid: cid.to_vec(),
            what,
        });
    }

    /// One need ahead of the rest; false when it can't be held.
    fn push_first(&mut self, core: &mut Core, cid: &[u8], what: What) -> bool {
        if !self.needs_room(core, 1, cid.len()) {
            return false;
        }
        self.add_need(cid, what);
        self.needs.rotate_right(1);
        true
    }

    /// The need at the front, taken; its CID's hold goes once the caller
    /// has used it.
    fn take_need(&mut self) -> Option<Need> {
        self.needs.pop_front()
    }

    /// Moves the walk on: identity blocks resolved in place, blocks that
    /// came read in order, the sources fed.
    fn pump(&mut self, core: &mut Core) {
        loop {
            if !matches!(self.stage, Stage::Dag) || core.ended() {
                return;
            }
            let Some(front) = self.needs.front() else {
                if self.hamt.is_some() {
                    self.hamt_done(core);
                    continue;
                }
                return self.done(core);
            };
            // An identity CID carries its block.
            let identity = ipfs_cid::parse(&front.cid)
                .filter(|c| c.hash == IDENTITY)
                .map(|c| c.digest.to_vec());
            let seq = front.seq;
            if let Some(block) = identity {
                if let Some(need) = self.take_need() {
                    let n = need.cid.len();
                    self.consume(core, need, block);
                    core.unhold(n);
                }
                continue;
            }
            if let Some(block) = self.arrived.remove(&seq) {
                if let Some(need) = self.take_need() {
                    let n = need.cid.len() + block.len();
                    self.consume(core, need, block);
                    core.unhold(n);
                }
                continue;
            }
            if self.car_verdicts(core) {
                // Room for more of the CAR.
                self.read_car(core);
                continue;
            }
            break;
        }
        self.feed(core);
    }

    /// The CAR's sections whose verdicts came, in order: each must be the
    /// block needed next. Whether any was used.
    fn car_verdicts(&mut self, core: &mut Core) -> bool {
        let Some(c) = self.car.as_mut() else {
            return false;
        };
        let Some((cid, block, verdict)) = c.verdicts.remove(&c.done) else {
            return false;
        };
        c.done += 1;
        let held = cid.len() + block.len() + SECTION_COST;
        c.pending = c.pending.saturating_sub(held);
        if let Err(r) = verdict {
            core.unhold(held);
            self.end(core, refusal(r));
            return true;
        }
        let same = self.needs.front().is_some_and(|front| {
            match (ipfs_cid::parse(&cid), ipfs_cid::parse(&front.cid)) {
                (Some(a), Some(b)) => a.same_block(&b),
                _ => false,
            }
        });
        if !same {
            // Not the block the walk needs next: the CAR stops being
            // useful, and the rest comes as raw blocks.
            core.unhold(held);
            self.close_car(core);
            self.raw_only = true;
            return true;
        }
        if let Some(need) = self.take_need() {
            let n = need.cid.len();
            self.consume(core, need, block);
            core.unhold(n);
        }
        core.unhold(held);
        true
    }

    /// Asks for what the walk needs: a CAR, or raw blocks.
    fn feed(&mut self, core: &mut Core) {
        if !matches!(self.stage, Stage::Dag) || core.ended() {
            return;
        }
        self.feed_car(core);
        if self.car.is_some() {
            return;
        }
        // Raw blocks for the needs ahead, within the bound and the memory,
        // and none while the body waits for the page: it holds the gateway
        // back, as it holds the CAR.
        if core.awaiting() >= QUEUE_LIMIT {
            return;
        }
        let pending: Vec<Need> = self
            .needs
            .iter()
            .filter(|n| {
                !self.raw.contains_key(&n.seq)
                    && !self.arrived.contains_key(&n.seq)
                    && ipfs_cid::parse(&n.cid).is_some_and(|c| c.hash != IDENTITY)
            })
            .take(MAX_RAW_PIECES)
            .cloned()
            .collect();
        for need in pending {
            if self.raw.len() >= MAX_RAW_PIECES {
                break;
            }
            // A raw leaf at its `blocksizes` entry, which its length must
            // equal; any other block at the limit (0009, Raw blocks).
            let leaf = ipfs_cid::parse(&need.cid).is_some_and(|c| c.codec == ipfs_cid::RAW);
            let block_room = match need.what {
                What::File { len, .. } if leaf => usize::try_from(len)
                    .unwrap_or(fc_ipfs::block::MAX_BLOCK)
                    .min(fc_ipfs::block::MAX_BLOCK),
                _ => fc_ipfs::block::MAX_BLOCK,
            };
            let reserve = block_room + need.cid.len();
            let first = self.needs.front().is_some_and(|f| f.seq == need.seq);
            if !core.fits(reserve + super::STREAM_WINDOW) {
                if first && self.raw.is_empty() {
                    return self.end(core, Failure::Unverifiable);
                }
                break;
            }
            let path = format!("/ipfs/{}?format=raw", display(&need.cid));
            let headers = vec![("accept".to_owned(), RAW_ACCEPT.to_owned())];
            let Some(id) = core.fetch(
                Tag::Raw(need.seq),
                path,
                headers,
                Ask::Stream(Some(fc_ipfs::block::MAX_BLOCK)),
            ) else {
                break;
            };
            core.hold(reserve);
            self.raw.insert(
                need.seq,
                RawPiece {
                    id,
                    buf: Vec::new(),
                    reserved: block_room,
                    cid_len: need.cid.len(),
                    hashing: false,
                },
            );
        }
    }

    /// A CAR for the next entity, when CARs are still worth asking for and
    /// none is open: the root's path at first, then the index document.
    fn feed_car(&mut self, core: &mut Core) {
        if self.raw_only || self.car.is_some() || !self.raw.is_empty() {
            return;
        }
        let Some(front) = self.needs.front() else {
            return;
        };
        let target = match front.what {
            What::Path(0) => format!("/ipfs/{}{}", self.root_text, self.car_path()),
            What::Index => format!("/ipfs/{}", display(&front.cid)),
            // A CAR ended before the walk did: raw from here.
            _ => {
                self.raw_only = true;
                return self.feed(core);
            }
        };
        if !core.fits(CAR_ROOM + super::STREAM_WINDOW) {
            self.raw_only = true;
            return self.feed(core);
        }
        let mut path = format!("{target}?format=car&dag-scope=entity");
        if let Some(bytes) = self.entity_bytes(core.head_only) {
            path.push_str("&entity-bytes=");
            path.push_str(&bytes);
        }
        let headers = vec![("accept".to_owned(), CAR_ACCEPT.to_owned())];
        let Some(id) = core.fetch(Tag::Car, path, headers, Ask::Stream(None)) else {
            self.raw_only = true;
            return self.feed(core);
        };
        core.hold(CAR_ROOM);
        self.car = Some(CarStream {
            finished: false,
            id,
            reader: car::Reader::new(),
            headed: false,
            open: true,
            stash: VecDeque::new(),
            sent: 0,
            done: 0,
            verdicts: BTreeMap::new(),
            pending: 0,
            ended: false,
            broken: None,
        });
    }

    /// The path a CAR resolves: the request's below an IPFS root; an IPNS
    /// value's path and the request's, below the resolved root.
    fn car_path(&self) -> String {
        if self.ipns.is_none() {
            let p = &self.raw_path;
            return if p.is_empty() {
                String::new()
            } else {
                format!("/{p}")
            };
        }
        let mut out = String::new();
        for s in &self.segments {
            out.push('/');
            out.push_str(&gateway::encode_path(&[s]));
        }
        out
    }

    /// `entity-bytes` for the request's range, read as the gateway reads
    /// one; the root alone for a range `GatewayCore` refuses, and for a
    /// HEAD the bytes its type is sniffed from.
    fn entity_bytes(&self, head_only: bool) -> Option<String> {
        if head_only {
            // The root, and the bytes a type is sniffed from.
            return Some(format!("0:{}", gateway::SNIFF_LAST));
        }
        if let Some(range) = self.asked.range.as_deref() {
            let one = range
                .strip_prefix("bytes=")
                .filter(|s| !s.contains(','))
                .and_then(|s| s.split_once('-'));
            return Some(match one {
                Some((a, "")) if a.parse::<u64>().is_ok() => format!("{a}:*"),
                Some(("", n)) if n.parse::<u64>().is_ok_and(|n| n > 0) => format!("-{n}:*"),
                Some((a, b)) if a.parse::<u64>().is_ok() && b.parse::<u64>().is_ok() => {
                    format!("{a}:{b}")
                }
                _ => "0:0".to_owned(),
            });
        }
        None
    }

    /// The needs are met.
    fn done(&mut self, core: &mut Core) {
        if self.file.as_ref().is_some_and(|f| !f.headed) {
            // A file shorter than its sniff: the type from what it has.
            self.head_file(core);
        }
        if core.ended() {
            return;
        }
        self.stop(core);
        core.finish();
    }

    /// A block the walk needed, checked, in its turn.
    fn consume(&mut self, core: &mut Core, need: Need, block: Vec<u8>) {
        let r = match need.what {
            What::Path(seg) => self.node(core, seg, &need.cid, &block),
            What::PathShard { seg, level } => self.path_shard(core, seg, level, &block),
            What::EntityShard { level } => self.entity_shard(core, level, &need.cid, &block),
            What::Index => self.index(core, &need.cid, &block),
            What::File { start, len, depth } => {
                self.file_node(core, &need.cid, &block, start, len, depth)
            }
        };
        if let Err(f) = r {
            self.end(core, f);
        }
    }

    /// The node reached after `seg` segments.
    fn node(
        &mut self,
        core: &mut Core,
        seg: usize,
        cid: &[u8],
        block: &[u8],
    ) -> Result<(), Failure> {
        let Some(c) = ipfs_cid::parse(cid) else {
            return Err(Failure::VerificationFailed);
        };
        if seg < self.segments.len() {
            if c.codec == ipfs_cid::RAW {
                self.page(
                    core,
                    502,
                    "unixfs error: path requires a directory but found file",
                );
                return Ok(());
            }
            let node = dagpb::decode(block).map_err(refusal)?;
            let data = unixfs::decode(&node).map_err(refusal)?;
            let name = self.segments[seg].clone();
            match data.kind {
                Kind::Directory => match node.links().find(|l| l.name == Some(name.as_str())) {
                    Some(link) => {
                        if !self.push_first(core, link.cid.bytes, What::Path(seg + 1)) {
                            return Err(Failure::Unverifiable);
                        }
                    }
                    None => self.page(core, 404, "not found"),
                },
                Kind::HamtShard => {
                    self.hamt_step(core, seg, 0, &node, data.data.unwrap_or(&[]), &name);
                }
                Kind::File | Kind::Raw => {
                    self.page(
                        core,
                        502,
                        "unixfs error: path requires a directory but found file",
                    );
                }
                Kind::Symlink | Kind::Metadata => self.unsupported(core, data.kind),
            }
            return Ok(());
        }
        // The entity.
        if c.codec == ipfs_cid::RAW {
            self.serve_path(core, None)?;
            return self.start_file(core, block, None);
        }
        let node = dagpb::decode(block).map_err(refusal)?;
        let data = unixfs::decode(&node).map_err(refusal)?;
        match data.kind {
            Kind::File | Kind::Raw => {
                self.serve_path(core, None)?;
                self.start_file(core, block, Some((&node, &data)))
            }
            Kind::Directory => {
                if let Some(link) = node.links().find(|l| l.name == Some("index.html")) {
                    if !self.push_first(core, link.cid.bytes, What::Index) {
                        return Err(Failure::Unverifiable);
                    }
                    return Ok(());
                }
                // The entries, borrowed from the block: their slots held
                // before they are taken.
                let named = |l: &dagpb::Link<'_>| l.name.is_some_and(|n| !n.is_empty());
                let n = node.links().filter(named).count();
                let held = n.saturating_mul(std::mem::size_of::<gateway::Entry<'_>>());
                if !core.fits(held) {
                    return Err(Failure::Unverifiable);
                }
                core.hold(held);
                let mut entries = Vec::with_capacity(n);
                for (at, l) in node.links().enumerate() {
                    if let Some(name) = l.name.filter(|n| !n.is_empty()) {
                        entries.push(gateway::Entry {
                            name: Cow::Borrowed(name),
                            size: l.tsize,
                            at,
                        });
                    }
                }
                self.listing(core, entries, held);
                Ok(())
            }
            Kind::HamtShard => {
                let held = block.len() + cid.len() + MAP_ENTRY;
                if !core.fits(held) {
                    return Err(Failure::Unverifiable);
                }
                core.hold(held);
                let mut h = Hamt {
                    root: cid.to_vec(),
                    held,
                    ..Hamt::default()
                };
                h.shards.insert(cid.to_vec(), block.to_vec());
                self.hamt = Some(h);
                if !self.push_shards(core, &node, 1) {
                    return Err(Failure::Unverifiable);
                }
                Ok(())
            }
            Kind::Symlink | Kind::Metadata => {
                self.unsupported(core, data.kind);
                Ok(())
            }
        }
    }

    fn unsupported(&mut self, core: &mut Core, kind: Kind) {
        let n = if kind == Kind::Symlink { 4 } else { 3 };
        self.page(
            core,
            502,
            &format!("unixfs error: unsupported unixfs node type {n}"),
        );
    }

    /// A shard's sub-shards (links named by the bucket's two digits alone),
    /// in link order, ahead of the rest: each read whole for the listing.
    /// False when they can't be held.
    fn push_shards(&mut self, core: &mut Core, node: &dagpb::Node<'_>, level: usize) -> bool {
        let sub = |l: &dagpb::Link<'_>| l.name.is_some_and(|n| n.len() == 2);
        let (mut n, mut cids) = (0, 0);
        for l in node.links().filter(sub) {
            n += 1;
            cids += l.cid.bytes.len();
        }
        if !self.needs_room(core, n, cids) {
            return false;
        }
        for l in node.links().filter(sub) {
            self.add_need(l.cid.bytes, What::EntityShard { level });
        }
        self.needs.rotate_right(n);
        true
    }

    /// The listing's entries in every shard below `cid`, depth-first in
    /// link order: each link named past its bucket's two digits.
    fn hamt_entries<'a>(
        shards: &'a BTreeMap<Vec<u8>, Vec<u8>>,
        cid: &[u8],
        depth: usize,
        f: &mut dyn FnMut(&'a [u8], Option<u64>),
    ) {
        if depth >= hamt::MAX_LEVELS {
            return;
        }
        let Some(block) = shards.get(cid) else {
            return;
        };
        let Ok(node) = dagpb::decode(block) else {
            return;
        };
        for l in node.links() {
            let label = l.name.unwrap_or("").as_bytes();
            if label.len() == 2 {
                Self::hamt_entries(shards, l.cid.bytes, depth + 1, f);
            } else if let Some(name) = label.get(2..).filter(|n| !n.is_empty()) {
                f(name, l.tsize);
            }
        }
    }

    fn hamt_step(
        &mut self,
        core: &mut Core,
        seg: usize,
        level: usize,
        node: &dagpb::Node<'_>,
        bitfield: &[u8],
        name: &str,
    ) {
        if level >= hamt::MAX_LEVELS {
            return self.end(core, Failure::Unverifiable);
        }
        let pushed = match hamt::step(node, bitfield, name, level) {
            Step::Entry(link) => self.push_first(core, link.cid.bytes, What::Path(seg + 1)),
            Step::Shard(link) => self.push_first(
                core,
                link.cid.bytes,
                What::PathShard {
                    seg,
                    level: level + 1,
                },
            ),
            Step::Absent => {
                self.page(core, 404, "not found");
                true
            }
        };
        if !pushed {
            self.end(core, Failure::Unverifiable);
        }
    }

    fn path_shard(
        &mut self,
        core: &mut Core,
        seg: usize,
        level: usize,
        block: &[u8],
    ) -> Result<(), Failure> {
        let node = dagpb::decode(block).map_err(refusal)?;
        let data = unixfs::decode(&node).map_err(refusal)?;
        if data.kind != Kind::HamtShard {
            self.page(
                core,
                502,
                "unixfs error: invalid dag-pb: HAMT bucket link did not resolve to a HAMT shard",
            );
            return Ok(());
        }
        let name = self.segments[seg].clone();
        self.hamt_step(core, seg, level, &node, data.data.unwrap_or(&[]), &name);
        Ok(())
    }

    fn entity_shard(
        &mut self,
        core: &mut Core,
        level: usize,
        cid: &[u8],
        block: &[u8],
    ) -> Result<(), Failure> {
        if level >= hamt::MAX_LEVELS {
            return Err(Failure::Unverifiable);
        }
        let node = dagpb::decode(block).map_err(refusal)?;
        let data = unixfs::decode(&node).map_err(refusal)?;
        if data.kind != Kind::HamtShard {
            self.page(
                core,
                502,
                "unixfs error: invalid dag-pb: HAMT bucket link did not resolve to a HAMT shard",
            );
            return Ok(());
        }
        let Some(h) = self.hamt.as_mut() else {
            return Err(Failure::Unverifiable);
        };
        // A shard linked twice is held once.
        if !h.shards.contains_key(cid) {
            let held = block.len() + cid.len() + MAP_ENTRY;
            if !core.fits(held) {
                return Err(Failure::Unverifiable);
            }
            core.hold(held);
            h.held += held;
            h.shards.insert(cid.to_vec(), block.to_vec());
        }
        if !self.push_shards(core, &node, level + 1) {
            return Err(Failure::Unverifiable);
        }
        Ok(())
    }

    /// Every shard is in: `index.html` by its hash, or the listing.
    fn hamt_done(&mut self, core: &mut Core) {
        let Some(h) = self.hamt.take() else {
            return;
        };
        let mut at = h.root.clone();
        let mut found = None;
        for level in 0..hamt::MAX_LEVELS {
            let Some(block) = h.shards.get(&at) else {
                break;
            };
            let Ok(node) = dagpb::decode(block) else {
                break;
            };
            let Ok(data) = unixfs::decode(&node) else {
                break;
            };
            match hamt::step(&node, data.data.unwrap_or(&[]), "index.html", level) {
                Step::Entry(link) => {
                    found = Some(link.cid.bytes.to_vec());
                    break;
                }
                Step::Shard(link) => at = link.cid.bytes.to_vec(),
                Step::Absent => break,
            }
        }
        if let Some(cid) = found {
            core.unhold(h.held);
            if !self.push_first(core, &cid, What::Index) {
                self.end(core, Failure::Unverifiable);
            }
            return;
        }
        // The entries, borrowed from the shards: their slots, and any name
        // that must be made valid UTF-8, held before they are taken.
        let (mut n, mut owned) = (0usize, 0usize);
        Self::hamt_entries(&h.shards, &h.root, 0, &mut |name, _| {
            n += 1;
            if std::str::from_utf8(name).is_err() {
                owned += name
                    .utf8_chunks()
                    .map(|c| c.valid().len() + if c.invalid().is_empty() { 0 } else { 3 })
                    .sum::<usize>();
            }
        });
        let held = n
            .saturating_mul(std::mem::size_of::<gateway::Entry<'_>>())
            .saturating_add(owned);
        if !core.fits(held) {
            core.unhold(h.held);
            return self.end(core, Failure::Unverifiable);
        }
        core.hold(held);
        let mut entries = Vec::with_capacity(n);
        Self::hamt_entries(&h.shards, &h.root, 0, &mut |name, size| {
            let name = match std::str::from_utf8(name) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => Cow::Owned(String::from_utf8_lossy(name).into_owned()),
            };
            let at = entries.len();
            entries.push(gateway::Entry { name, size, at });
        });
        self.listing(core, entries, held);
        core.unhold(h.held);
    }

    /// Room for path strings of at most `bytes` in `n` segments, held
    /// before they are built; false when the request can't hold them.
    fn reserve_path(&mut self, core: &mut Core, n: usize, bytes: usize) -> bool {
        let need = bytes.saturating_add(n.saturating_mul(std::mem::size_of::<String>()));
        if !core.fits(need) {
            return false;
        }
        core.hold(need);
        self.path_held += need;
        true
    }

    /// The path strings' hold, brought to what they hold now.
    fn settle_path(&mut self, core: &mut Core) {
        let now =
            strings_cost(&self.rest) + strings_cost(&self.segments) + strings_cost(&self.served);
        if now < self.path_held {
            core.unhold(self.path_held - now);
        } else {
            core.hold(now - self.path_held);
        }
        self.path_held = now;
    }

    /// The served path: the walked segments, and the index document's name
    /// for a directory.
    fn serve_path(&mut self, core: &mut Core, last: Option<&str>) -> Result<(), Failure> {
        let n = self.segments.len() + usize::from(last.is_some());
        let bytes = self.segments.iter().map(String::len).sum::<usize>() + last.map_or(0, str::len);
        if !self.reserve_path(core, n, bytes) {
            return Err(Failure::Unverifiable);
        }
        let mut served = Vec::with_capacity(n);
        served.extend(self.segments.iter().cloned());
        served.extend(last.map(str::to_owned));
        self.served = served;
        self.settle_path(core);
        Ok(())
    }

    fn index(&mut self, core: &mut Core, cid: &[u8], block: &[u8]) -> Result<(), Failure> {
        self.serve_path(core, Some("index.html"))?;
        if ipfs_cid::parse(cid).is_some_and(|c| c.codec == ipfs_cid::RAW) {
            return self.start_file(core, block, None);
        }
        let node = dagpb::decode(block).map_err(refusal)?;
        let data = unixfs::decode(&node).map_err(refusal)?;
        match data.kind {
            Kind::File | Kind::Raw => self.start_file(core, block, Some((&node, &data))),
            Kind::Directory | Kind::HamtShard => {
                self.page(core, 400, "directory path could not be served");
                Ok(())
            }
            Kind::Symlink | Kind::Metadata => {
                self.unsupported(core, data.kind);
                Ok(())
            }
        }
    }

    /// `GatewayCore`'s listing of the directory reached, from its entries,
    /// which hold `held` bytes of the request's memory. The page is counted,
    /// its room held, then written into a buffer of exactly that length.
    fn listing(&mut self, core: &mut Core, mut entries: Vec<gateway::Entry<'_>>, held: usize) {
        if self.asked.range.is_some() {
            drop(entries);
            core.unhold(held);
            return self.page(
                core,
                400,
                "Range requests are not supported for directory listings",
            );
        }
        let (title, base) = match &self.ipns {
            None => {
                let shown = self.shown_path();
                let title = if shown.is_empty() {
                    format!("/ipfs/{}", self.root_text)
                } else {
                    format!("/ipfs/{}/{shown}", self.root_text)
                };
                let enc = gateway::encode_path(&self.segments);
                let base = if enc.is_empty() {
                    format!("/ipfs/{}", self.root_text)
                } else {
                    format!("/ipfs/{}/{enc}", self.root_text)
                };
                (title, base)
            }
            Some(name) => {
                let shown = self.shown_path();
                let title = if shown.is_empty() {
                    format!("/ipns/{name}")
                } else {
                    format!("/ipns/{name}/{shown}")
                };
                let mut segs = vec![name.clone()];
                segs.extend(self.rest_segments());
                (title, format!("/ipns/{}", gateway::encode_path(&segs)))
            }
        };
        gateway::sort_listing(&mut entries);
        let len = gateway::listing_len(&title, &base, &entries);
        if !core.fits(len) {
            drop(entries);
            core.unhold(held);
            return self.end(core, Failure::Unverifiable);
        }
        core.hold(len);
        let (h, body) = gateway::listing(&title, &base, &entries, len);
        drop(entries);
        core.unhold(held);
        self.stop(core);
        core.head(200, h, self.label);
        core.body(body, None);
        core.finish();
    }

    /// The request's path as written, each segment decoded.
    fn shown_path(&self) -> String {
        if self.raw_path.is_empty() {
            return String::new();
        }
        fc_ipfs::path::decode_segments(&self.raw_path)
            .map(|s| s.join("/"))
            .unwrap_or_default()
    }

    fn rest_segments(&self) -> Vec<String> {
        segments(&format!("/{}", self.raw_path))
            .unwrap_or_default()
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect()
    }

    // The file.

    /// The file's root is in: the tag, the conditional, the range, then
    /// its content.
    fn start_file(
        &mut self,
        core: &mut Core,
        block: &[u8],
        node: Option<(&dagpb::Node<'_>, &unixfs::Data<'_>)>,
    ) -> Result<(), Failure> {
        let len = match node {
            None => block.len() as u64,
            Some((_, d)) => d.filesize.ok_or(Failure::Malformed)?,
        };
        let etag = gateway::etag(&self.root_text, &self.served, len);
        if self.asked.range.is_none()
            && self
                .asked
                .if_none_match
                .as_deref()
                .is_some_and(|v| gateway::if_none_match(v, &etag))
        {
            self.stop(core);
            core.head(304, gateway::not_modified(&etag, self.cache), self.label);
            core.finish();
            return Ok(());
        }
        let range = match self.asked.range.as_deref() {
            None => None,
            Some(v) => match gateway::parse_range(v, len) {
                Ok(r) => Some(r),
                Err(RangeError::BadRequest(detail)) => {
                    self.page(core, 400, detail);
                    return Ok(());
                }
                Err(RangeError::NotSatisfiable) => {
                    self.page(core, 416, "range not satisfiable");
                    return Ok(());
                }
            },
        };
        let mime = gateway::type_by_extension(&self.served);
        let sniff = if mime.is_none() {
            gateway::sniff_end(len, range)
        } else {
            None
        };
        let (a, b) = match (range, sniff) {
            // A HEAD needs the bytes its type is sniffed from, no more.
            (_, Some(end)) if core.head_only => (0, end),
            (Some((s, e)), _) => (s, e),
            (None, _) => (0, len.saturating_sub(1)),
        };
        self.file = Some(File {
            a,
            b,
            len,
            sniff,
            headed: false,
            early: Vec::new(),
            mime,
            etag,
            range,
        });
        // Nothing more is needed for the head: send it now. Otherwise the
        // first bytes come first.
        if sniff.is_none() {
            self.head_file(core);
            if core.ended() || len == 0 {
                return Ok(());
            }
        }
        // The needs below the root are the file's only: what the path's
        // CAR or the index's carries next.
        self.content(core, block, node, 0, len, 0)
    }

    /// The head of the file being served.
    fn head_file(&mut self, core: &mut Core) {
        let Some(f) = self.file.as_mut() else {
            return;
        };
        if f.headed {
            return;
        }
        f.headed = true;
        let mime = match &f.mime {
            Some(m) => m.clone(),
            None => gateway::sniffed(&f.early),
        };
        let headers = match f.range {
            Some((s, e)) => gateway::partial(&mime, s, e, f.len, &f.etag, self.cache),
            None => gateway::whole(&mime, f.len, &f.etag, self.cache),
        };
        let status = if f.range.is_some() { 206 } else { 200 };
        let early = std::mem::take(&mut f.early);
        core.head(status, headers, self.label);
        if core.ended() {
            // A HEAD: nothing past the head.
            core.unhold(early.len());
            self.stop(core);
            return;
        }
        self.release(core, &early, 0);
        core.unhold(early.len());
        if self.file.as_ref().is_some_and(|f| f.len == 0) {
            self.stop(core);
            core.finish();
        }
    }

    /// A file node's content: its own data at `start`, then its children
    /// within the body, read in turn.
    fn content(
        &mut self,
        core: &mut Core,
        block: &[u8],
        node: Option<(&dagpb::Node<'_>, &unixfs::Data<'_>)>,
        start: u64,
        len: u64,
        depth: usize,
    ) -> Result<(), Failure> {
        let Some((node, data)) = node else {
            // A raw leaf: the block is the content, and its length is the
            // one its parent declared (deviation `unixfs-sizes`).
            if block.len() as u64 != len {
                return Err(Failure::Malformed);
            }
            self.emit(core, start, block);
            return Ok(());
        };
        if !matches!(data.kind, Kind::File | Kind::Raw) || data.filesize != Some(len) {
            return Err(Failure::Malformed);
        }
        let inline = data.data.unwrap_or(&[]);
        self.emit(core, start, inline);
        let Some(f) = self.file.as_ref() else {
            return Ok(());
        };
        let (a, b) = (f.a, f.b);
        let first = start + inline.len() as u64;
        // The children within the body, each with its offset: counted and
        // their room held, then queued ahead of what follows the node.
        let within = || {
            let mut at = first;
            node.links()
                .zip(data.blocksizes())
                .filter_map(move |(link, size)| {
                    let child = at;
                    at += size;
                    (size != 0 && child + size > a && child <= b).then_some((link, child, size))
                })
        };
        let (mut n, mut cids) = (0, 0);
        for (link, _, _) in within() {
            n += 1;
            cids += link.cid.bytes.len();
        }
        if n > 0 && depth + 1 >= MAX_FILE_DEPTH {
            return Err(Failure::Unverifiable);
        }
        if !self.needs_room(core, n, cids) {
            return Err(Failure::Unverifiable);
        }
        for (link, child, size) in within() {
            self.add_need(
                link.cid.bytes,
                What::File {
                    start: child,
                    len: size,
                    depth: depth + 1,
                },
            );
        }
        self.needs.rotate_right(n);
        Ok(())
    }

    fn file_node(
        &mut self,
        core: &mut Core,
        cid: &[u8],
        block: &[u8],
        start: u64,
        len: u64,
        depth: usize,
    ) -> Result<(), Failure> {
        if ipfs_cid::parse(cid).is_some_and(|c| c.codec == ipfs_cid::RAW) {
            return self.content(core, block, None, start, len, depth);
        }
        let node = dagpb::decode(block).map_err(refusal)?;
        let data = unixfs::decode(&node).map_err(refusal)?;
        self.content(core, block, Some((&node, &data)), start, len, depth)
    }

    /// Content at `start`: before the head, what the sniff waits for; after
    /// it, what the body's range holds.
    fn emit(&mut self, core: &mut Core, start: u64, bytes: &[u8]) {
        let Some(f) = self.file.as_mut() else {
            return;
        };
        if !f.headed {
            // Only bytes 0 to the sniff's end are kept for the type, as
            // `GatewayCore` reads no more; the head goes once they're in.
            let end = f.sniff.unwrap_or(0);
            if start <= end {
                let keep = usize::try_from(end + 1 - start)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                core.hold(keep);
                f.early.extend_from_slice(&bytes[..keep]);
            }
            let past = end + 1;
            if start + bytes.len() as u64 >= past {
                self.head_file(core);
                // The rest of this slice, past the sniffed bytes.
                if self.file.as_ref().is_some_and(|f| f.headed) && !core.ended() {
                    let from = usize::try_from(past.saturating_sub(start)).unwrap_or(usize::MAX);
                    if let Some(tail) = bytes.get(from..).filter(|t| !t.is_empty()) {
                        self.release(core, tail, start.max(past));
                    }
                }
            }
            return;
        }
        self.release(core, bytes, start);
    }

    /// The body's part of `bytes` at `start`: blocks come depth-first, so
    /// their content in order.
    fn release(&mut self, core: &mut Core, bytes: &[u8], start: u64) {
        let Some(f) = self.file.as_ref() else {
            return;
        };
        let lo = f.a.max(start);
        let hi = (f.b + 1).min(start + bytes.len() as u64);
        if hi <= lo {
            return;
        }
        let (Ok(from), Ok(to)) = (usize::try_from(lo - start), usize::try_from(hi - start)) else {
            return;
        };
        let Some(part) = bytes.get(from..to) else {
            return;
        };
        core.hold(part.len());
        core.body(part.to_vec(), None);
    }

    // The sources' events.

    fn car_data(&mut self, core: &mut Core, bytes: Vec<u8>) {
        let Some(c) = self.car.as_mut() else {
            core.unhold(bytes.len());
            return;
        };
        c.stash.push_back(bytes);
        self.read_car(core);
        self.pump(core);
    }

    /// Feeds the stash to the CAR reader, and the sections it completes to
    /// the hashing pool; once the stream has ended and its stash is read,
    /// judges how it ended.
    fn read_car(&mut self, core: &mut Core) {
        let Some(c) = self.car.as_mut() else {
            return;
        };
        if let Err(failure) = Self::push_frames(c, core) {
            Self::break_car(c, core, failure);
            return self.car_settled(core);
        }
        if c.finished && !c.ended && c.stash.is_empty() {
            match c.reader.finish() {
                Ok(End::Complete) => {}
                // The sections before the break are still used.
                Ok(End::Early) => c.broken = Some(Failure::Stopped),
                Err(r) => c.broken = Some(refusal(r)),
            }
            c.ended = true;
            self.car_settled(core);
        }
    }

    /// Framing the reader can't take: nothing more is read, and once the
    /// sections before it are used, the walk ends with it.
    fn break_car(c: &mut CarStream, core: &mut Core, failure: Failure) {
        if c.open {
            c.open = false;
            core.cancel_piece(c.id);
        }
        core.unhold(c.stash.iter().map(Vec::len).sum());
        c.stash.clear();
        c.ended = true;
        c.broken.get_or_insert(failure);
    }

    /// Frames into the reader while the body the page hasn't read has room
    /// (any once the stream has ended: nothing is held back then), as much
    /// of each as can complete no more sections than may still wait, each
    /// counted with its job's structures; and only while the request has
    /// room for what those bytes can complete: the section being read and
    /// the bytes themselves.
    fn push_frames(c: &mut CarStream, core: &mut Core) -> Result<(), Failure> {
        while c.finished || core.awaiting() < QUEUE_LIMIT {
            let starts = PENDING_LIMIT.saturating_sub(c.pending) / SECTION_COST;
            if starts == 0 {
                // The sections waiting free room as their verdicts are used.
                return Ok(());
            }
            let Some(frame) = c.stash.front_mut() else {
                return Ok(());
            };
            // The item being read completes with the bytes it wants; each
            // further section takes at least MIN_SECTION.
            let wanting = c.reader.wanting();
            let further = if wanting > 0 { starts - 1 } else { starts };
            let most = wanting
                .saturating_add(further.saturating_mul(car::MIN_SECTION))
                .saturating_add(car::MIN_SECTION - 1);
            let take = frame.len().min(most);
            if !core.fits(c.reader.holding() + take) {
                // Room comes back as sections are used and the body is
                // read; with neither waiting, it never will.
                if c.pending == 0 && core.awaiting() == 0 {
                    return Err(Failure::Unverifiable);
                }
                return Ok(());
            }
            let pushed = c.reader.push(&frame[..take]);
            frame.drain(..take);
            if frame.is_empty() {
                c.stash.pop_front();
            }
            // The bytes are the reader's now, within its room.
            core.unhold(take);
            if c.open {
                core.consumed(c.id, take);
            }
            for section in pushed.sections {
                let n = c.sent;
                c.sent += 1;
                // The section's own buffer, the CID moved out of its front.
                let (mut block, cid_len) = section.into_parts();
                let cid = block.drain(..cid_len).collect::<Vec<u8>>();
                let size = cid.len() + block.len();
                // The section's bytes were in the reader's room and the
                // frame's; its job's own structures need room of their own.
                if !core.fits(SECTION_COST) {
                    return Err(Failure::Unverifiable);
                }
                c.pending += size + SECTION_COST;
                core.hold(size + SECTION_COST);
                core.hash(Tag::Section(n), Work::Block { cid, block });
            }
            if let Some(r) = pushed.error {
                return Err(refusal(r));
            }
        }
        Ok(())
    }

    fn car_end(&mut self, core: &mut Core) {
        let Some(c) = self.car.as_mut() else {
            return;
        };
        c.open = false;
        // What it stashed is read first.
        c.finished = true;
        self.read_car(core);
    }

    /// A CAR that ended cleanly and whose sections are all judged gives
    /// way: the next entity's CAR, or raw blocks.
    fn car_settled(&mut self, core: &mut Core) {
        let settled = self
            .car
            .as_ref()
            .is_some_and(|c| c.ended && c.done == c.sent);
        if settled {
            if let Some(f) = self.car.as_ref().and_then(|c| c.broken)
                && !self.needs.is_empty()
            {
                return self.end(core, f);
            }
            self.close_car(core);
            // The CAR carried the path's entity; another CAR only for the
            // index document.
            if !self.needs.front().is_some_and(|n| n.what == What::Index) {
                self.raw_only = true;
            }
        }
        self.pump(core);
    }

    fn raw_data(&mut self, core: &mut Core, seq: u64, bytes: Vec<u8>) {
        let Some(r) = self.raw.get_mut(&seq) else {
            core.unhold(bytes.len());
            return;
        };
        let n = bytes.len();
        // The block's room was held; its bytes take it as they come. Bytes
        // past it (a node longer than a leaf's entry) need room of their
        // own.
        let take = n.min(r.reserved);
        if n > take && !core.fits(n - take) {
            core.unhold(n);
            return self.end(core, Failure::Unverifiable);
        }
        r.buf.extend_from_slice(&bytes);
        r.reserved -= take;
        core.unhold(take);
        core.consumed(r.id, n);
    }

    fn raw_end(&mut self, core: &mut Core, seq: u64) {
        let Some(need) = self.needs.iter().find(|n| n.seq == seq).cloned() else {
            if let Some(r) = self.raw.remove(&seq) {
                core.unhold(r.held());
            }
            return;
        };
        let Some(r) = self.raw.get_mut(&seq) else {
            return;
        };
        r.hashing = true;
        core.unhold(r.reserved);
        r.reserved = 0;
        // The block and its CID are the job's now.
        r.cid_len = 0;
        let block = std::mem::take(&mut r.buf);
        core.hash(
            Tag::Raw(seq),
            Work::Block {
                cid: need.cid,
                block,
            },
        );
    }

    fn whole_record(&mut self, core: &mut Core, status: u16, body: Vec<u8>) {
        let Stage::Record { name, .. } = &self.stage else {
            core.unhold(body.len());
            return;
        };
        if status != 200 {
            core.unhold(body.len());
            return self.end(core, Failure::Status(status));
        }
        let Some(cid) = ipfs_cid::from_key_text(name) else {
            core.unhold(body.len());
            return self.end(core, Failure::Unverifiable);
        };
        core.hold(cid.len());
        core.hash(
            Tag::Record,
            Work::Record {
                name: cid,
                record: body,
                now: self.asked.now,
            },
        );
    }
}

impl super::Events<Tag> for Walk {
    fn whole(
        &mut self,
        core: &mut Core,
        tag: Tag,
        status: u16,
        _headers: &[(String, String)],
        body: Vec<u8>,
    ) {
        match tag {
            Tag::Record => self.whole_record(core, status, body),
            _ => core.unhold(body.len()),
        }
    }

    fn stream_head(
        &mut self,
        core: &mut Core,
        tag: Tag,
        _id: PieceId,
        status: u16,
        headers: &[(String, String)],
    ) {
        match tag {
            Tag::Car => {
                let Some(c) = self.car.as_mut() else {
                    return;
                };
                c.headed = true;
                let typed = header(headers, "content-type").is_some_and(car_type_ok);
                if status == 200 && typed {
                    return;
                }
                if status == 200 {
                    // Another type or parameters (`dups=n` among them):
                    // not read; the walk's blocks come raw.
                    self.close_car(core);
                    self.raw_only = true;
                    return self.pump(core);
                }
                // Any other status is the gateway's final answer.
                self.end(core, Failure::Status(status));
            }
            Tag::Raw(seq) if status != 200 => {
                if let Some(r) = self.raw.remove(&seq) {
                    core.unhold(r.held());
                    core.cancel_piece(r.id);
                }
                self.end(core, Failure::Status(status));
            }
            _ => {}
        }
    }

    fn stream_data(&mut self, core: &mut Core, tag: Tag, _id: PieceId, bytes: Vec<u8>) {
        match tag {
            Tag::Car => self.car_data(core, bytes),
            Tag::Raw(seq) => self.raw_data(core, seq, bytes),
            _ => core.unhold(bytes.len()),
        }
    }

    fn room(&mut self, core: &mut Core) {
        self.read_car(core);
        self.pump(core);
    }

    fn stream_end(&mut self, core: &mut Core, tag: Tag, _id: PieceId) {
        match tag {
            Tag::Car => self.car_end(core),
            Tag::Raw(seq) => self.raw_end(core, seq),
            _ => {}
        }
    }

    fn failed(&mut self, core: &mut Core, tag: Tag, failure: PieceFailure) {
        if let Tag::Raw(seq) = tag
            && let Some(r) = self.raw.remove(&seq)
        {
            core.unhold(r.held());
        }
        if tag == Tag::Car
            && let Some(c) = self.car.as_mut()
        {
            // The sections it sent before failing are still used.
            c.open = false;
            c.ended = true;
            c.broken = Some(Failure::Piece(failure));
            return self.car_settled(core);
        }
        self.end(core, Failure::Piece(failure));
    }

    fn hashed(&mut self, core: &mut Core, tag: Tag, verdict: Verdict, work: Work) {
        match (tag, verdict, work) {
            (Tag::Record, Verdict::Record(result), Work::Record { name, record, .. }) => {
                core.unhold(name.len() + record.len());
                let Stage::Record { hop, .. } = self.stage else {
                    return;
                };
                match result {
                    // `GatewayCore` resolves a fourth name, then refuses
                    // whatever it names.
                    Ok(_) if hop > MAX_RESOLUTIONS => {
                        self.page(core, 400, "dnslink recursion limit exceeded");
                    }
                    Ok(r) => self.record_value(core, &r.value, hop),
                    Err(e) => self.end(core, refusal(e)),
                }
            }
            (Tag::Section(n), Verdict::Block(result), Work::Block { cid, block }) => {
                let Some(c) = self.car.as_mut() else {
                    core.unhold(cid.len() + block.len());
                    return;
                };
                c.verdicts.insert(n, (cid, block, result));
                self.pump(core);
                if self.car.is_some() {
                    self.car_settled(core);
                }
            }
            (Tag::Raw(seq), Verdict::Block(result), Work::Block { cid, block }) => {
                core.unhold(cid.len());
                self.raw.remove(&seq);
                if let Err(r) = result {
                    core.unhold(block.len());
                    return self.end(core, refusal(r));
                }
                if self.needs.iter().any(|n| n.seq == seq) {
                    self.arrived.insert(seq, block);
                } else {
                    core.unhold(block.len());
                }
                self.pump(core);
            }
            (_, _, work) => core.unhold(work.size()),
        }
    }
}
