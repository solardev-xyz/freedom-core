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
/// Verified body waiting for main's credit past which no more stream
/// bytes are read: the page holds the gateway back.
const QUEUE_LIMIT: usize = 512 << 10;
const CAR_ACCEPT: &str = "application/vnd.ipld.car; version=1; order=dfs; dups=y";
const RAW_ACCEPT: &str = "application/vnd.ipld.raw";
const RECORD_ACCEPT: &str = "application/vnd.ipfs.ipns-record";
/// Sections hashing or waiting their turn past which the CAR isn't read
/// further: the walk holds the gateway back.
const PENDING_LIMIT: usize = 2 << 20;
/// A CAR's reading room: one section and the header.
const CAR_ROOM: usize = car::MAX_SECTION + car::MAX_HEADER;

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
/// `index.html` lookup by hash, and its entries.
#[derive(Debug, Default)]
struct Hamt {
    root: Vec<u8>,
    shards: BTreeMap<Vec<u8>, Vec<u8>>,
    entries: Vec<gateway::Entry>,
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
    next_seq: u64,
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
            next_seq: 0,
            arrived: BTreeMap::new(),
            raw: BTreeMap::new(),
            raw_only,
            car: None,
            hamt: None,
            file: None,
            served: Vec::new(),
        };
        let Some(rest) = segments(path) else {
            walk.page(core, 400, "path traversal segments are not allowed");
            return Ok(walk);
        };
        if rest.len() > MAX_SEGMENTS {
            core.fail(Failure::Unverifiable);
            return Ok(walk);
        }
        match root {
            Root::Ipfs(text) => {
                let cid = ipfs_cid::from_base32(text).ok_or(PlanRefusal::Root)?;
                walk.resolved(core, cid, rest);
            }
            Root::Ipns(name) => {
                walk.ipns = Some(name.clone());
                walk.rest = rest;
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
        self.needs.clear();
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
            core.unhold(h.shards.values().map(Vec::len).sum());
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
            for (_, (cid, block, _)) in c.verdicts {
                core.unhold(cid.len() + block.len());
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
        let mut inner: Vec<String> = below
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        match ns {
            "ipfs" => {
                let Some(cid) = cid_from_text(target) else {
                    return self.end(core, Failure::Unverifiable);
                };
                inner.append(&mut self.rest.clone());
                self.resolved(core, cid, inner);
            }
            "ipns" => {
                // A name with a key the core verifies is followed; DNSLink,
                // or another key, can't be.
                if !matches!(
                    crate::verify::ipns_name_kind(target),
                    crate::verify::NameKind::Ed25519 | crate::verify::NameKind::Sha256
                ) {
                    return self.end(core, Failure::Unverifiable);
                }
                let mut rest = inner;
                rest.append(&mut self.rest);
                self.rest = rest;
                self.ask_record(core, target.to_owned(), hop + 1);
            }
            _ => self.end(core, Failure::VerificationFailed),
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
        self.root = root.clone();
        self.segments = inner.into_iter().filter(|s| !s.is_empty()).collect();
        self.stage = Stage::Dag;
        self.push_back(root, What::Path(0));
        self.pump(core);
    }

    fn push_back(&mut self, cid: Vec<u8>, what: What) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.needs.push_back(Need { seq, cid, what });
    }

    /// The children of the node just read, ahead of what follows it.
    fn push_front(&mut self, children: Vec<(Vec<u8>, What)>) {
        for (cid, what) in children.into_iter().rev() {
            let seq = self.next_seq;
            self.next_seq += 1;
            self.needs.push_front(Need { seq, cid, what });
        }
    }

    /// Moves the walk on: identity blocks resolved in place, blocks that
    /// came read in order, the sources fed.
    fn pump(&mut self, core: &mut Core) {
        loop {
            if !matches!(self.stage, Stage::Dag) || core.ended() {
                return;
            }
            let Some(front) = self.needs.front().cloned() else {
                if self.hamt.is_some() {
                    self.hamt_done(core);
                    continue;
                }
                return self.done(core);
            };
            // An identity CID carries its block.
            if let Some(cid) = ipfs_cid::parse(&front.cid)
                && cid.hash == IDENTITY
            {
                let block = cid.digest.to_vec();
                self.needs.pop_front();
                self.consume(core, front, block);
                continue;
            }
            if let Some(block) = self.arrived.remove(&front.seq) {
                self.needs.pop_front();
                core.unhold(block.len());
                self.consume(core, front, block);
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
        c.pending = c.pending.saturating_sub(cid.len() + block.len());
        core.unhold(cid.len() + block.len());
        if let Err(r) = verdict {
            self.end(core, refusal(r));
            return true;
        }
        let Some(front) = self.needs.front().cloned() else {
            return true;
        };
        let same = match (ipfs_cid::parse(&cid), ipfs_cid::parse(&front.cid)) {
            (Some(a), Some(b)) => a.same_block(&b),
            _ => false,
        };
        if !same {
            // Not the block the walk needs next: the CAR stops being
            // useful, and the rest comes as raw blocks.
            self.close_car(core);
            self.raw_only = true;
            return true;
        }
        self.needs.pop_front();
        self.consume(core, front, block);
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
        if core.queued() > QUEUE_LIMIT {
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
                        self.push_front(vec![(link.cid.bytes.to_vec(), What::Path(seg + 1))]);
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
            self.served = self.segments.clone();
            return self.start_file(core, block, None);
        }
        let node = dagpb::decode(block).map_err(refusal)?;
        let data = unixfs::decode(&node).map_err(refusal)?;
        match data.kind {
            Kind::File | Kind::Raw => {
                self.served = self.segments.clone();
                self.start_file(core, block, Some((&node, &data)))
            }
            Kind::Directory => {
                if let Some(link) = node.links().find(|l| l.name == Some("index.html")) {
                    self.push_front(vec![(link.cid.bytes.to_vec(), What::Index)]);
                    return Ok(());
                }
                let entries = node
                    .links()
                    .filter_map(|l| {
                        let name = l.name.filter(|n| !n.is_empty())?;
                        Some(gateway::Entry {
                            name: name.to_owned(),
                            size: l.tsize,
                        })
                    })
                    .collect();
                self.listing(core, entries);
                Ok(())
            }
            Kind::HamtShard => {
                if !core.fits(block.len()) {
                    return Err(Failure::Unverifiable);
                }
                core.hold(block.len());
                let mut h = Hamt {
                    root: cid.to_vec(),
                    ..Hamt::default()
                };
                h.shards.insert(cid.to_vec(), block.to_vec());
                let children = Self::shard_entries(&node, &mut h.entries, 1);
                self.hamt = Some(h);
                self.push_front(children);
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

    /// A shard's entries (links named past the bucket's two digits), and
    /// its sub-shards to read, in link order.
    fn shard_entries(
        node: &dagpb::Node<'_>,
        entries: &mut Vec<gateway::Entry>,
        level: usize,
    ) -> Vec<(Vec<u8>, What)> {
        let mut children = Vec::new();
        for l in node.links() {
            let name = l.name.unwrap_or("");
            if name.len() == 2 {
                children.push((l.cid.bytes.to_vec(), What::EntityShard { level }));
            } else if name.len() > 2 {
                entries.push(gateway::Entry {
                    name: String::from_utf8_lossy(&name.as_bytes()[2..]).into_owned(),
                    size: l.tsize,
                });
            }
        }
        children
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
        match hamt::step(node, bitfield, name, level) {
            Step::Entry(link) => {
                self.push_front(vec![(link.cid.bytes.to_vec(), What::Path(seg + 1))]);
            }
            Step::Shard(link) => {
                self.push_front(vec![(
                    link.cid.bytes.to_vec(),
                    What::PathShard {
                        seg,
                        level: level + 1,
                    },
                )]);
            }
            Step::Absent => self.page(core, 404, "not found"),
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
        if !core.fits(block.len()) {
            return Err(Failure::Unverifiable);
        }
        core.hold(block.len());
        let Some(h) = self.hamt.as_mut() else {
            return Err(Failure::Unverifiable);
        };
        h.shards.insert(cid.to_vec(), block.to_vec());
        let children = Self::shard_entries(&node, &mut h.entries, level + 1);
        self.push_front(children);
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
        core.unhold(h.shards.values().map(Vec::len).sum());
        match found {
            Some(cid) => self.push_front(vec![(cid, What::Index)]),
            None => self.listing(core, h.entries),
        }
    }

    fn index(&mut self, core: &mut Core, cid: &[u8], block: &[u8]) -> Result<(), Failure> {
        let mut served = self.segments.clone();
        served.push("index.html".to_owned());
        self.served = served;
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

    /// `GatewayCore`'s listing of the directory reached.
    fn listing(&mut self, core: &mut Core, mut entries: Vec<gateway::Entry>) {
        if self.asked.range.is_some() {
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
        let (h, body) = gateway::listing(&title, &base, &mut entries);
        self.answer(core, 200, h, body);
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
        let mut at = start + inline.len() as u64;
        let mut children = Vec::new();
        for (link, size) in node.links().zip(data.blocksizes()) {
            let child_start = at;
            at += size;
            if size == 0 || child_start + size <= a || child_start > b {
                continue;
            }
            if depth + 1 >= MAX_FILE_DEPTH {
                return Err(Failure::Unverifiable);
            }
            children.push((
                link.cid.bytes.to_vec(),
                What::File {
                    start: child_start,
                    len: size,
                    depth: depth + 1,
                },
            ));
        }
        self.push_front(children);
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
            let end = f.sniff.unwrap_or(0);
            if start <= end {
                core.hold(bytes.len());
                f.early.extend_from_slice(bytes);
            }
            if start + bytes.len() as u64 > end {
                self.head_file(core);
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

    /// Frames into the reader while the body and the sections waiting have
    /// room (any once the stream has ended: nothing is held back then), and
    /// while the request has room for what the next frame can complete:
    /// the section being read and the frame's own bytes.
    fn push_frames(c: &mut CarStream, core: &mut Core) -> Result<(), Failure> {
        while c.finished || (core.queued() <= QUEUE_LIMIT && c.pending <= PENDING_LIMIT) {
            let Some(frame) = c.stash.front() else {
                return Ok(());
            };
            if !core.fits(c.reader.holding() + frame.len()) {
                // Room comes back as sections are used and the body is
                // read; with neither waiting, it never will.
                if c.pending == 0 && core.queued() == 0 {
                    return Err(Failure::Unverifiable);
                }
                return Ok(());
            }
            let Some(frame) = c.stash.pop_front() else {
                return Ok(());
            };
            let pushed = c.reader.push(&frame);
            // The frame's bytes are the reader's now, within its room.
            core.unhold(frame.len());
            if c.open {
                core.consumed(c.id, frame.len());
            }
            for section in pushed.sections {
                let n = c.sent;
                c.sent += 1;
                // The section's own buffer, the CID moved out of its front.
                let (mut block, cid_len) = section.into_parts();
                let cid = block.drain(..cid_len).collect::<Vec<u8>>();
                let size = cid.len() + block.len();
                c.pending += size;
                core.hold(size);
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
