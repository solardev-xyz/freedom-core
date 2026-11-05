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
//!
//! **Its memory** (0009, What a grant covers) is all [`Charged`] values,
//! as the Swarm walk's is: the walk doesn't import the raw hold and release
//! ([`super::Holding`]), so a charge goes only with its value, after it.
//! What the walk answers (a page, a listing, a head with nothing after it,
//! the end, a failure) waits in [`Walk::answer`] until the input is done
//! with the block it came from ([`Walk::conclude`]): by then everything the
//! walk held has gone, each value before its charge, and the core may drop
//! the walk's holding. The walk's copies of the request's path and name
//! are charged too; only its range and tag ([`Asked`]), which the machine
//! takes from the plan's headers, are the machine's.

use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};

use fc_ipfs::Refusal as BlockRefusal;
use fc_ipfs::car::{self, End};
use fc_ipfs::cid::{self as ipfs_cid, IDENTITY, SHA2_256};
use fc_ipfs::dagpb;
use fc_ipfs::hamt::{self, Step};
use fc_ipfs::unixfs::{self, Kind};

use super::charged::Charged;
use super::gateway::{self, Cache, RangeError};
use super::jobs::{Verdict, Work};
use super::{Ask, Failure, PieceFailure, PieceId, STREAM_WINDOW, Stash};
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
pub(super) const MAP_ENTRY: usize = 128;
/// The most sections one push into the CAR reader completes: the vector
/// it gives them in stays within [`SECTIONS_ROOM`].
const PUSH_SECTIONS: usize = 64;
/// Room for the reader's vector of sections while they are given out: at
/// most [`PUSH_SECTIONS`] slots, and the half as many it moved from as it
/// grew.
const SECTIONS_ROOM: usize =
    (PUSH_SECTIONS + PUSH_SECTIONS / 2) * std::mem::size_of::<car::Section>();
/// A head's headers beside its type and tag: their names, the fixed and
/// numeric values, a sniffed type and the vector's slots.
const HEAD_ROOM: usize = 1024;
/// A type by its extension while it is made, and as it is kept.
const MIME_ROOM: usize = 256;
/// An error page's fixed text, its title and its status.
const PAGE_TEXT: usize = 512;

/// Bytes the walk holds, under their charge.
type Bytes = Charged<Vec<u8>>;
/// A head's headers.
type Headers = Vec<(String, String)>;

/// Where reading a CAR stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Read {
    /// Read as far as it can for now.
    On,
    /// No room to read on, and nothing that will give it back: the CAR
    /// gives way to raw blocks.
    GiveWay,
}

/// Whether `n` more bytes have room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Room {
    Fits,
    /// Not now: room comes back as the page reads the body, a job's result
    /// or a piece's end comes, and the walk tries again then.
    Wait,
    /// Nothing out will give room back.
    No,
}

/// Why using a block stopped short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Halt {
    /// The walk ends with this.
    Fail(Failure),
    /// The block waits for room ([`Room::Wait`]): it and its need are
    /// kept, and used again once room comes back. Nothing it did before
    /// stopping has gone out.
    Wait,
}

impl From<Failure> for Halt {
    fn from(f: Failure) -> Self {
        Self::Fail(f)
    }
}

/// What came of the CAR's next verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Turn {
    /// None is in its turn.
    None,
    /// Used, or the CAR ended by it.
    Used,
    /// Its block waits for room ([`Halt::Wait`]).
    Parked,
}

/// The room held for a block asked for: a raw leaf at its `blocksizes`
/// entry, which its length must equal; any other block at the limit (0009,
/// Raw blocks).
fn block_room(need: &Need) -> usize {
    block_len(need).unwrap_or(fc_ipfs::block::MAX_BLOCK)
}

/// A raw leaf's length, as its entry gives it.
fn block_len(need: &Need) -> Option<usize> {
    let leaf = ipfs_cid::parse(&need.cid).is_some_and(|c| c.codec == ipfs_cid::RAW);
    match need.what {
        What::File { len, .. } if leaf => Some(
            usize::try_from(len)
                .unwrap_or(fc_ipfs::block::MAX_BLOCK)
                .min(fc_ipfs::block::MAX_BLOCK),
        ),
        _ => None,
    }
}

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
/// `dups=y`, in any order, each once, and no other parameter. Read in
/// place: the gateway's header makes nothing the walk would hold.
fn car_type_ok(value: &str) -> bool {
    const WANTED: [(&str, &str); 3] = [("dups", "y"), ("order", "dfs"), ("version", "1")];
    let mut parts = value.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|t| t.eq_ignore_ascii_case("application/vnd.ipld.car"))
    {
        return false;
    }
    let mut seen = [false; 3];
    for (k, v) in parts
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.split_once('='))
    {
        let (k, v) = (k.trim(), v.trim());
        let at = WANTED
            .iter()
            .position(|(wk, wv)| k.eq_ignore_ascii_case(wk) && v.eq_ignore_ascii_case(wv));
        match at {
            Some(i) if !seen[i] => seen[i] = true,
            _ => return false,
        }
    }
    seen == [true; 3]
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

/// A CID decoded from `text` by `decode`, made within room for all that
/// decoding holds at once (the text's copy, its bytes, and their copy as
/// they are checked: each at most the text's length), and charged what it
/// holds: `Ok(None)`, its room gone, when the text isn't one, and `Err`
/// when the room doesn't fit.
fn charged_cid(
    core: &mut Core,
    text: &str,
    decode: impl FnOnce(&str) -> Option<Vec<u8>>,
) -> Result<Option<Bytes>, Failure> {
    let room = Charged::room(core, 3 * text.len()).ok_or(Failure::Memory)?;
    Ok(room
        .try_map(core, |()| decode(text))
        .map(|cid| cid.remake(core, |cid| cid)))
}

/// A CID as `GatewayCore` shows it: a CIDv0 in base58, a CIDv1 in base32.
fn display(cid: &[u8]) -> String {
    ipfs_cid::parse(cid).map_or_else(String::new, |c| ipfs_cid::to_text(&c))
}

/// Room for a CID's text ([`display`]) while it is made: base32 or base58
/// takes under twice the CID's bytes, its string at most twice that as it
/// grows.
fn text_room(cid: &[u8]) -> usize {
    4 * cid.len() + 16
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

/// A path's segments, each decoded once; `None` when one is refused.
fn segments(path: &str) -> Option<Vec<String>> {
    let below = path.strip_prefix('/').unwrap_or(path);
    if below.is_empty() {
        return Some(Vec::new());
    }
    fc_ipfs::path::decode_segments(below)
}

/// Room for a file's tag ([`gateway::etag`]) while it is made: the root's
/// text and the served path percent-encoded, and the string at most twice
/// that as it grows, beside the encoded path.
fn etag_room(root_text: &str, served: &[String]) -> usize {
    let encoded = 3 * served.iter().map(String::len).sum::<usize>() + served.len();
    2 * (root_text.len() + encoded + 32) + encoded
}

/// Room for an error page with `detail`: its body (the fixed text and the
/// detail escaped, at most six bytes a byte), at most twice that as it
/// grows, beside the escaped detail as it is made; and its headers.
fn page_room(detail: &str) -> usize {
    HEAD_ROOM + 2 * (PAGE_TEXT + 6 * detail.len()) + 12 * detail.len()
}

/// `name` made valid UTF-8 as `String::from_utf8_lossy` makes it, in a
/// string of exactly its length: [`Walk::hamt_done`] counted it.
fn lossy(name: &[u8]) -> String {
    let len = name
        .utf8_chunks()
        .map(|c| c.valid().len() + if c.invalid().is_empty() { 0 } else { 3 })
        .sum::<usize>();
    let mut out = String::with_capacity(len);
    for c in name.utf8_chunks() {
        out.push_str(c.valid());
        if !c.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out
}

/// `slot`'s value gives way to `value`: the old one goes, then its charge.
fn put<T>(core: &mut Core, slot: &mut Charged<T>, value: Charged<T>) {
    std::mem::replace(slot, value).release(core);
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

/// A block the walk needs, in the needs' queue: the queue is charged its
/// slots, and the CIDs together beside it ([`Walk::cids`]).
#[derive(Debug)]
pub(super) struct Need {
    seq: u64,
    cid: Vec<u8>,
    what: What,
}

/// A need taken from the queue, its CID now under a charge of its own.
#[derive(Debug)]
struct Taken {
    seq: u64,
    cid: Bytes,
    what: What,
}

/// A raw block asked for.
#[derive(Debug)]
struct RawPiece {
    id: PieceId,
    /// Its length is known: a leaf whose entry gives it.
    exact: bool,
    state: Raw,
}

/// Where a raw block stands.
#[derive(Debug)]
enum Raw {
    /// Its bytes are coming in. `buf` is the block's buffer
    /// ([`next_size`]), made at its first byte, charged the room held for
    /// it: the block's bound, or the buffer's capacity once that is more.
    /// `cid` is room for the CID its job will hold.
    Reading { buf: Bytes, cid: Charged<()> },
    /// The block, its whole buffer, is its job's, which counts it.
    Hashing,
}

impl RawPiece {
    /// It goes with all it holds.
    fn release(self, core: &mut Core) {
        match self.state {
            Raw::Reading { buf, cid } => {
                buf.release(core);
                cid.release(core);
            }
            Raw::Hashing => {}
        }
    }
}

/// A block buffer's next size, for `len` bytes. A leaf's is its length,
/// made once. A block of unknown length (a node, read into a block's
/// bound) starts at a frame's, then takes half its room and its window,
/// and only past that all its room: each move, the old buffer beside the
/// new and main's frame, fits the room and the window but the last, whose
/// rest is held for it ([`Walk::raw_data`]); and a buffer cut to its
/// block's length at its end fits them too, up to the half.
fn next_size(buf: &Bytes, exact: bool, len: usize) -> usize {
    let (cap, room) = (buf.capacity(), buf.cost());
    let half = (room + STREAM_WINDOW) / 2;
    let next = if exact || cap >= half.min(room) {
        room
    } else if cap == 0 {
        super::MAX_FRAME.min(room)
    } else {
        half.min(room)
    };
    next.max(len)
}

/// A section judged: its CID, its block, its job's structures' room, and
/// the verdict.
#[derive(Debug)]
struct Judged {
    cid: Bytes,
    block: Bytes,
    cost: Charged<()>,
    verdict: Result<(), BlockRefusal>,
}

impl Judged {
    fn release(self, core: &mut Core) {
        self.cid.release(core);
        self.block.release(core);
        self.cost.release(core);
    }
}

/// The CAR being read.
#[derive(Debug)]
struct CarStream {
    id: PieceId,
    reader: car::Reader,
    /// The reader's room ([`CAR_ROOM`]).
    room: Charged<()>,
    headed: bool,
    open: bool,
    /// Bytes not yet given to the reader, while the body waits for credit:
    /// in one buffer of the stream's window.
    stash: Stash,
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
    early: Bytes,
    /// The type by the served path's extension, and the tag.
    mime: Charged<Option<String>>,
    etag: Charged<String>,
    /// Room for the head's headers, until the head has them.
    head: Option<Charged<()>>,
    range: Option<(u64, u64)>,
}

impl File {
    fn release(self, core: &mut Core) {
        self.early.release(core);
        self.mime.release(core);
        self.etag.release(core);
        if let Some(h) = self.head {
            h.release(core);
        }
    }
}

/// Where the walk stands.
#[derive(Debug)]
enum Stage {
    /// The record of `name` asked for; `hop` resolutions so far. Once the
    /// record is hashing, `result` is room for what its job's result holds
    /// (the record's value and validity, each a part of it).
    Record {
        name: Charged<String>,
        hop: usize,
        result: Option<Charged<()>>,
    },
    /// The record passed; its value waits for the partition's floor.
    Floor {
        hop: usize,
        value: Charged<String>,
    },
    Dag,
    Done,
}

/// The directory reached, when it is a HAMT: its shards, for the
/// `index.html` lookup by hash, then the listing. Charged as `charged.rs`
/// measures it.
#[derive(Debug, Default)]
pub(super) struct Hamt {
    pub(super) root: Vec<u8>,
    pub(super) shards: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// What the walk answers, given to the core once the input is done with
/// the block it came from ([`Walk::conclude`]).
#[derive(Debug)]
enum Answer {
    /// The walk fails: an error before the head, an abort after.
    Fail(Failure),
    /// `GatewayCore`'s page for an error the walk proved, made then.
    Page { status: u16, detail: &'static str },
    /// A head made within `room`, and the body that is all there is, or
    /// none: a listing, a 304, a HEAD's file.
    Head {
        status: u16,
        headers: Headers,
        room: Charged<()>,
        body: Option<Bytes>,
    },
    /// The body is complete.
    Finish,
}

impl Answer {
    /// An answer that came second: it goes, and its charges.
    fn release(self, core: &mut Core) {
        if let Self::Head {
            headers,
            room,
            body,
            ..
        } = self
        {
            drop(headers);
            room.release(core);
            if let Some(b) = body {
                b.release(core);
            }
        }
    }
}

/// The request's IPFS walk.
#[derive(Debug)]
pub(crate) struct Walk {
    asked: Asked,
    /// The request path below the root or name, as written.
    raw_path: Charged<String>,
    /// For IPNS: the name the request asked for, and its path's segments.
    ipns: Option<Charged<String>>,
    rest: Charged<Vec<String>>,
    stage: Stage,
    /// The resolved root's text as `GatewayCore` shows it, and the
    /// segments below it.
    root_text: Charged<String>,
    segments: Charged<Vec<String>>,
    cache: Cache,
    label: ContentTrust,
    /// The blocks the walk needs, in order: the queue charged its slots,
    /// and room for their CIDs, each CID's capacity, beside it. A need
    /// taken out takes its CID's part of the room with it.
    needs: Charged<VecDeque<Need>>,
    cids: Charged<()>,
    next_seq: u64,
    /// Blocks checked, waiting for their turn: by need, each charged its
    /// buffer, all of it.
    arrived: BTreeMap<u64, Bytes>,
    raw: BTreeMap<u64, RawPiece>,
    /// Raw blocks only, from here on.
    raw_only: bool,
    car: Option<CarStream>,
    /// The structures of the CAR sections' jobs out ([`SECTION_COST`]
    /// each), whose results haven't come: each goes with its verdict, even
    /// once the CAR has.
    sections: Charged<()>,
    hamt: Option<Charged<Hamt>>,
    file: Option<File>,
    /// The served path's segments (the index document's, for a directory).
    served: Charged<Vec<String>>,
    /// Room held for the body bytes the block in use copies out, until they
    /// are copied ([`Walk::draw`]).
    copy: Option<Charged<()>>,
    /// What the walk answers, once the input is done ([`Walk::conclude`]).
    answer: Option<Answer>,
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
            raw_path: Charged::nothing(core),
            ipns: None,
            rest: Charged::nothing(core),
            stage: Stage::Done,
            root_text: Charged::nothing(core),
            segments: Charged::nothing(core),
            cache: Cache::Immutable,
            label: ContentTrust::Verified,
            needs: Charged::nothing(core),
            cids: Charged::new(core, (), 0),
            next_seq: 0,
            arrived: BTreeMap::new(),
            raw: BTreeMap::new(),
            raw_only,
            car: None,
            sections: Charged::new(core, (), 0),
            hamt: None,
            file: None,
            served: Charged::nothing(core),
            copy: None,
            answer: None,
        };
        let begun = walk.begin(core, root, path);
        walk.conclude(core);
        begun.map(|()| walk)
    }

    fn begin(&mut self, core: &mut Core, root: &Root, path: &str) -> Result<(), PlanRefusal> {
        // The request's segments and its path as written: their room held
        // before they are built, an empty segment's slot included, which
        // the walk drops later.
        let n = path.split('/').filter(|s| !s.is_empty()).count();
        if n > MAX_SEGMENTS {
            self.end(core, Failure::Unverifiable);
            return Ok(());
        }
        let slots = path.split('/').count();
        let below = path.strip_prefix('/').unwrap_or(path);
        // Nothing is out yet: room that doesn't fit never will.
        let Ok(mut room) = self.path_room(core, slots, path.len() + below.len()) else {
            self.end(core, Failure::Memory);
            return Ok(());
        };
        let raw = room.split(below.len()).map(|()| below.to_owned());
        put(core, &mut self.raw_path, raw);
        let Some(rest) = segments(path) else {
            room.release(core);
            self.page(core, 400, "path traversal segments are not allowed");
            return Ok(());
        };
        let rest = room.remake(core, |()| rest);
        match root {
            Root::Ipfs(text) => match charged_cid(core, text, ipfs_cid::from_base32) {
                Ok(Some(cid)) => self.resolved(core, cid, rest),
                Ok(None) => {
                    rest.release(core);
                    return Err(PlanRefusal::Root);
                }
                Err(f) => {
                    rest.release(core);
                    self.end(core, f);
                }
            },
            Root::Ipns(name) => {
                put(core, &mut self.rest, rest);
                self.cache = Cache::Mutable;
                self.label = ContentTrust::LatestAsserted;
                // The name the request asked for, and the first record's.
                let Some(mut room) = Charged::room(core, 2 * name.len()) else {
                    self.end(core, Failure::Memory);
                    return Ok(());
                };
                self.ipns = Some(room.split(name.len()).map(|()| name.clone()));
                self.ask_record(core, room.map(|()| name.clone()), 1);
            }
            Root::Swarm(_) => {
                rest.release(core);
                return Err(PlanRefusal::Root);
            }
        }
        Ok(())
    }

    /// `GatewayCore`'s page for an error the walk proves, once every source
    /// is dropped ([`Answer::Page`]). It never waits for room: nothing is
    /// out before the DAG, and in it the page (under 1 KiB) is proved from
    /// the one block the walk needs, which came with more room beside it
    /// than that, a raw block's window or the CAR's reading room, free by
    /// the time the page is made.
    fn page(&mut self, core: &mut Core, status: u16, detail: &'static str) {
        self.answer(core, Answer::Page { status, detail });
    }

    fn end(&mut self, core: &mut Core, failure: Failure) {
        self.answer(core, Answer::Fail(failure));
    }

    /// The walk's answer: every source goes now, with what it holds, and
    /// the answer waits for the input's end ([`Walk::conclude`]). The first
    /// answer stands.
    fn answer(&mut self, core: &mut Core, answer: Answer) {
        self.stop(core);
        if self.answer.is_none() {
            self.answer = Some(answer);
        } else {
            answer.release(core);
        }
    }

    /// The walk has answered, or the request has ended.
    fn over(&self, core: &Core) -> bool {
        self.answer.is_some() || core.ended()
    }

    /// At the end of each input, the walk's answer goes to the core: the
    /// block it came from, and everything else the walk held, are gone by
    /// then, so the core may drop the walk's holding as the request ends.
    fn conclude(&mut self, core: &mut Core) {
        let Some(answer) = self.answer.take() else {
            return;
        };
        match answer {
            Answer::Fail(failure) => core.fail(failure),
            Answer::Finish => core.finish(),
            Answer::Page { status, detail } => {
                let Some(mut room) = Charged::room(core, page_room(detail)) else {
                    return core.fail(Failure::Memory);
                };
                let (headers, body) = gateway::error_page(status, detail);
                let body = room.split(body.capacity()).map(|()| body);
                self.head(core, status, headers, room, Some(body));
            }
            Answer::Head {
                status,
                headers,
                room,
                body,
            } => self.head(core, status, headers, room, body),
        }
    }

    /// A head and the body that is all there is. For a HEAD the body goes
    /// first, as the head ends the request.
    fn head(
        &self,
        core: &mut Core,
        status: u16,
        headers: Headers,
        room: Charged<()>,
        body: Option<Bytes>,
    ) {
        let body = match body {
            Some(b) if core.head_only => {
                b.release(core);
                None
            }
            body => body,
        };
        core.head_charged(status, headers, self.label, room);
        if let Some(body) = body {
            core.body_charged(body, None);
        }
        core.finish();
    }

    /// Drops every source and what it holds, and the path: once the walk
    /// answers, nothing of it is left but the answer.
    fn stop(&mut self, core: &mut Core) {
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::Record { name, result, .. } => {
                name.release(core);
                if let Some(r) = result {
                    r.release(core);
                }
            }
            Stage::Floor { value, .. } => value.release(core),
            Stage::Dag | Stage::Done => {}
        }
        let mut needs = std::mem::replace(&mut self.needs, Charged::nothing(core));
        needs.get_mut().clear();
        let cids = std::mem::replace(&mut self.cids, Charged::new(core, (), 0));
        cids.release(core);
        needs.release(core);
        for (_, b) in std::mem::take(&mut self.arrived) {
            b.release(core);
        }
        for (_, r) in std::mem::take(&mut self.raw) {
            let (id, reading) = (r.id, matches!(r.state, Raw::Reading { .. }));
            r.release(core);
            if reading {
                core.cancel_piece(id);
            }
        }
        self.close_car(core);
        let sections = std::mem::replace(&mut self.sections, Charged::new(core, (), 0));
        sections.release(core);
        if let Some(h) = self.hamt.take() {
            h.release(core);
        }
        if let Some(f) = self.file.take() {
            f.release(core);
        }
        self.drop_copy(core);
        for path in [&mut self.rest, &mut self.segments, &mut self.served] {
            let none = Charged::nothing(core);
            put(core, path, none);
        }
        for text in [&mut self.root_text, &mut self.raw_path] {
            let none = Charged::nothing(core);
            put(core, text, none);
        }
        if let Some(name) = self.ipns.take() {
            name.release(core);
        }
    }

    fn close_car(&mut self, core: &mut Core) {
        Self::release_car(self.car.take(), core);
    }

    /// Whether room the request holds can still come back: a raw block's
    /// window as it ends, a job's bytes (a section's, dropped once its CAR
    /// is gone), a cancelled piece's window at its end, the body as the page
    /// reads it.
    fn room_returns(&self, core: &Core) -> bool {
        !self.raw.is_empty() || core.hashing() || core.cancelling() || core.awaiting() > 0
    }

    /// Room for `n` more bytes. The CAR's reading room is a shortcut's:
    /// when `n` doesn't fit beside it, the walk waits while the page has
    /// body to read, and otherwise the CAR gives way, raw blocks carrying
    /// the walk on without it. Past the CAR, the walk waits while anything
    /// out can give room back ([`Walk::room_returns`]); with nothing out,
    /// the room never comes.
    fn room_for(&mut self, core: &mut Core, n: usize) -> Room {
        if core.fits(n) {
            return Room::Fits;
        }
        if self.car.is_some() {
            if core.awaiting() > 0 {
                return Room::Wait;
            }
            self.close_car(core);
            self.raw_only = true;
            if core.fits(n) {
                return Room::Fits;
            }
        }
        if self.room_returns(core) {
            Room::Wait
        } else {
            Room::No
        }
    }

    /// [`Walk::room_for`], as a step of the walk: on, or halted.
    fn make_room(&mut self, core: &mut Core, n: usize) -> Result<(), Halt> {
        match self.room_for(core, n) {
            Room::Fits => Ok(()),
            Room::Wait => Err(Halt::Wait),
            Room::No => Err(Failure::Memory.into()),
        }
    }

    /// [`Walk::make_room`], the room then held for what is to be made.
    fn reserve(&mut self, core: &mut Core, n: usize) -> Result<Charged<()>, Halt> {
        self.make_room(core, n)?;
        Charged::room(core, n).ok_or(Halt::Fail(Failure::Memory))
    }

    /// A need whose block waits for room: back at the front (its slot is
    /// the one it left), its CID's charge back with the queue's, its block,
    /// still held, among those arrived.
    fn park(&mut self, need: Taken, block: Option<Bytes>) {
        let Taken { seq, cid, what } = need;
        if let Some(b) = block {
            self.arrived.insert(seq, b);
        }
        let needs = &mut self.needs;
        let back = cid.map(|cid| needs.get_mut().push_front(Need { seq, cid, what }));
        self.cids.absorb(back);
    }

    /// Room for `n` bytes of body copied out of the block in use, from the
    /// room held for them ([`Walk::copy_bound`]).
    fn draw(&mut self, core: &mut Core, n: usize) -> Charged<()> {
        let mut room = match self.copy.as_mut() {
            Some(copy) => copy.split(n),
            None => Charged::new(core, (), 0),
        };
        debug_assert_eq!(room.cost(), n, "a body copy past the room held for it");
        if room.cost() < n {
            let more = n - room.cost();
            room.absorb(Charged::new(core, (), more));
        }
        room
    }

    /// Room for the copies of the block in use, which [`Walk::draw`] takes
    /// from.
    fn hold_copy(&mut self, core: &mut Core, room: Charged<()>) {
        self.drop_copy(core);
        self.copy = Some(room);
    }

    /// What is left of the room held for the copies goes.
    fn drop_copy(&mut self, core: &mut Core) {
        if let Some(copy) = self.copy.take() {
            copy.release(core);
        }
    }

    /// Room for the body bytes that content of `n` bytes at `start` copies
    /// out: its part of the body's range, and before the head the sniffed
    /// bytes twice (kept, then sent).
    fn copy_bound(&self, start: u64, n: usize) -> usize {
        let Some(f) = self.file.as_ref() else {
            return 0;
        };
        let lo = f.a.max(start);
        let hi = (f.b + 1).min(start.saturating_add(n as u64));
        let part = usize::try_from(hi.saturating_sub(lo)).unwrap_or(usize::MAX);
        let early = match f.sniff {
            Some(end) if !f.headed => usize::try_from(end + 1).unwrap_or(usize::MAX),
            _ => 0,
        };
        part.saturating_add(early.saturating_mul(2))
    }

    /// [`Walk::copy_bound`] for `need`'s block of at most `len` bytes, when
    /// it is a file node's. The walk's other blocks copy nothing out beside
    /// blocks asked after them: a path's, a shard's, and the entity's, which
    /// is asked alone.
    fn copy_estimate(&self, need: &Need, len: usize) -> usize {
        match need.what {
            What::File {
                start, len: size, ..
            } => self.copy_bound(start, len.min(usize::try_from(size).unwrap_or(usize::MAX))),
            _ => 0,
        }
    }

    /// The most that any block asked for and not yet used will copy out.
    fn copy_out(&self) -> usize {
        let mut left = self.raw.len() + self.arrived.len();
        let mut most = 0;
        for n in self.needs.iter() {
            if left == 0 {
                break;
            }
            let len = match self.arrived.get(&n.seq) {
                Some(b) => b.len(),
                None if self.raw.contains_key(&n.seq) => block_room(n),
                None => continue,
            };
            left -= 1;
            most = most.max(self.copy_estimate(n, len));
        }
        most
    }

    fn release_car(car: Option<CarStream>, core: &mut Core) {
        if let Some(c) = car {
            let CarStream {
                id,
                reader,
                room,
                open,
                mut stash,
                verdicts,
                ..
            } = c;
            if open {
                core.cancel_piece(id);
            }
            stash.free(core);
            // The reader goes, then its room.
            drop(reader);
            room.release(core);
            // Sections still hashing: their jobs' bytes come back with their
            // results, and go then, with their structures' room.
            for (_, j) in verdicts {
                j.release(core);
            }
        }
    }

    // IPNS.

    fn ask_record(&mut self, core: &mut Core, name: Charged<String>, hop: usize) {
        let path = format!("/ipns/{}?format=ipns-record", name.as_str());
        let headers = vec![("accept".to_owned(), RECORD_ACCEPT.to_owned())];
        self.stage = Stage::Record {
            name,
            hop,
            result: None,
        };
        if core
            .fetch(
                Tag::Record,
                path,
                headers,
                Ask::Whole(fc_ipfs::ipns::MAX_RECORD),
            )
            .is_none()
        {
            self.end(core, Failure::Memory);
        }
    }

    fn record_value(&mut self, core: &mut Core, value: &str, hop: usize) {
        let mut parts = value.splitn(4, '/');
        let (Some(""), Some(ns), Some(target)) = (parts.next(), parts.next(), parts.next()) else {
            return self.end(core, Failure::VerificationFailed);
        };
        let below = parts.next().unwrap_or("");
        // The CID within room for it. Nothing is out before the DAG: room
        // that doesn't fit never will.
        let cid = match ns {
            "ipfs" => match charged_cid(core, target, cid_from_text) {
                Ok(Some(cid)) => Some(cid),
                Ok(None) => return self.end(core, Failure::Unverifiable),
                Err(f) => return self.end(core, f),
            },
            "ipns" => None,
            _ => return self.end(core, Failure::VerificationFailed),
        };
        let fail = |walk: &mut Self, core: &mut Core, cid: Option<Bytes>, f: Failure| {
            if let Some(cid) = cid {
                cid.release(core);
            }
            walk.end(core, f);
        };
        // `GatewayCore` matches a value's segments as written, decoding
        // none, and refuses one that is `.` or `..`, as written or
        // percent-encoded, with its 400; a name's too (split_name_path).
        if (cid.is_none() && traversal(target)) || below.split('/').any(traversal) {
            if let Some(cid) = cid {
                cid.release(core);
            }
            return self.page(core, 400, "path traversal segments are not allowed");
        }
        // The value's segments ahead of the request's: at most 256 in all,
        // their room held before they are built.
        let n = below.split('/').filter(|s| !s.is_empty()).count();
        let total = n + self.rest.len();
        if total > MAX_SEGMENTS {
            return fail(self, core, cid, Failure::Unverifiable);
        }
        let Ok(room) = self.path_room(core, total, below.len()) else {
            return fail(self, core, cid, Failure::Memory);
        };
        let old = std::mem::replace(&mut self.rest, Charged::nothing(core));
        let inner = old.join(room).remake(core, |(mut old, ())| {
            let mut inner = Vec::with_capacity(total);
            inner.extend(
                below
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            );
            inner.append(&mut old);
            drop(old);
            inner
        });
        match cid {
            Some(cid) => self.resolved(core, cid, inner),
            None => {
                // A name with a key the core verifies is followed; DNSLink,
                // or another key, can't be.
                if !matches!(
                    crate::verify::ipns_name_kind(target),
                    crate::verify::NameKind::Ed25519 | crate::verify::NameKind::Sha256
                ) {
                    inner.release(core);
                    return self.end(core, Failure::Unverifiable);
                }
                put(core, &mut self.rest, inner);
                match Charged::make(core, target.len(), || target.to_owned()) {
                    Some(name) => self.ask_record(core, name, hop + 1),
                    None => self.end(core, Failure::Memory),
                }
            }
        }
    }

    // The DAG.

    /// The root is known: walk its path.
    fn resolved(&mut self, core: &mut Core, root: Bytes, inner: Charged<Vec<String>>) {
        let refused = match ipfs_cid::parse(&root) {
            None => Some(Failure::VerificationFailed),
            // A hash the native node doesn't verify (blake3, say).
            Some(c) if c.hash != SHA2_256 && c.hash != IDENTITY => Some(Failure::Unverifiable),
            Some(c) if c.codec != ipfs_cid::DAG_PB && c.codec != ipfs_cid::RAW => {
                Some(Failure::Unverifiable)
            }
            Some(_) => None,
        };
        if let Some(f) = refused {
            root.release(core);
            inner.release(core);
            return self.end(core, f);
        }
        // Nothing is out yet: room that doesn't fit never will.
        let Some(room) = Charged::room(core, text_room(&root)) else {
            root.release(core);
            inner.release(core);
            return self.end(core, Failure::Memory);
        };
        let text = room.remake(core, |()| display(&root));
        put(core, &mut self.root_text, text);
        let segments = inner.remake(core, |mut inner| {
            inner.retain(|s| !s.is_empty());
            inner
        });
        put(core, &mut self.segments, segments);
        self.stage = Stage::Dag;
        // The root's CID is the first need's.
        match self.needs_room(core, 1, 0) {
            Ok(room) => room.release(core),
            Err(_) => {
                root.release(core);
                return self.end(core, Failure::Memory);
            }
        }
        self.push_need(root, What::Path(0));
        self.pump(core);
    }

    /// Room for `n` more needs whose CIDs hold `cids` bytes: the queue
    /// grows within it (its new buffer beside the old one while it moves,
    /// charged what it holds after), and the CIDs' room is what is left
    /// ([`Walk::add_need`]).
    fn needs_room(&mut self, core: &mut Core, n: usize, cids: usize) -> Result<Charged<()>, Halt> {
        let slot = std::mem::size_of::<Need>();
        let cap = self.needs.capacity();
        let want = self.needs.len().saturating_add(n);
        let grown = if want > cap {
            want.saturating_mul(slot)
        } else {
            0
        };
        let mut room = self.reserve(core, grown.saturating_add(cids))?;
        if want > cap {
            self.needs.absorb(room.split(grown));
            self.needs.change(core, |needs| needs.reserve_exact(n));
        }
        Ok(room)
    }

    /// A need at the back, its CID copied within `room`, from
    /// [`Walk::needs_room`].
    fn add_need(&mut self, room: &mut Charged<()>, cid: &[u8], what: What) {
        let cid = room.split(cid.len()).map(|()| cid.to_vec());
        self.push_need(cid, what);
    }

    /// A need at the back, in a slot [`Walk::needs_room`] made: its CID's
    /// charge joins the CIDs' room.
    fn push_need(&mut self, cid: Bytes, what: What) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let needs = &mut self.needs;
        let queued = cid.map(|cid| needs.get_mut().push_back(Need { seq, cid, what }));
        self.cids.absorb(queued);
    }

    /// One need ahead of the rest.
    fn push_first(&mut self, core: &mut Core, cid: &[u8], what: What) -> Result<(), Halt> {
        let mut room = self.needs_room(core, 1, cid.len())?;
        self.add_need(&mut room, cid, what);
        room.release(core);
        self.needs.get_mut().rotate_right(1);
        Ok(())
    }

    /// The need at the front, taken, its CID with its part of the CIDs'
    /// room; the CID goes once the caller has used it.
    fn take_need(&mut self) -> Option<Taken> {
        let Need { seq, cid, what } = self.needs.get_mut().pop_front()?;
        let cid = self.cids.split(cid.capacity()).map(|()| cid);
        Some(Taken { seq, cid, what })
    }

    /// Moves the walk on: identity blocks resolved in place, blocks that
    /// came read in order, the sources fed. A block that waits for room
    /// ([`Halt::Wait`]) stops it, and nothing more is asked for: what comes
    /// back is the block's. A block in use goes before the walk's answer
    /// does ([`Walk::conclude`]).
    fn pump(&mut self, core: &mut Core) {
        loop {
            if !matches!(self.stage, Stage::Dag) || self.over(core) {
                return;
            }
            let Some(front) = self.needs.front() else {
                if self.hamt.is_some() {
                    match self.hamt_done(core) {
                        Ok(()) => continue,
                        Err(Halt::Wait) => return,
                        Err(Halt::Fail(f)) => return self.end(core, f),
                    }
                }
                return self.done(core);
            };
            // An identity CID carries its block: copied out, within room
            // held for it.
            let identity = ipfs_cid::parse(&front.cid)
                .filter(|c| c.hash == IDENTITY)
                .map(|c| c.digest.len());
            let seq = front.seq;
            if let Some(len) = identity {
                let room = match self.reserve(core, len) {
                    Ok(room) => room,
                    Err(Halt::Wait) => return,
                    Err(Halt::Fail(f)) => return self.end(core, f),
                };
                let Some(need) = self.take_need() else {
                    return room.release(core);
                };
                let block = room.map(|()| {
                    ipfs_cid::parse(&need.cid)
                        .map(|c| c.digest.to_vec())
                        .unwrap_or_default()
                });
                let used = self.consume(core, &need, &block);
                block.release(core);
                if used == Err(Halt::Wait) {
                    return self.park(need, None);
                }
                need.cid.release(core);
                if let Err(Halt::Fail(f)) = used {
                    self.end(core, f);
                }
                continue;
            }
            if let Some(block) = self.arrived.remove(&seq) {
                let Some(need) = self.take_need() else {
                    return block.release(core);
                };
                let used = self.consume(core, &need, &block);
                if used == Err(Halt::Wait) {
                    return self.park(need, Some(block));
                }
                block.release(core);
                need.cid.release(core);
                if let Err(Halt::Fail(f)) = used {
                    self.end(core, f);
                }
                continue;
            }
            match self.car_verdicts(core) {
                // Room for more of the CAR.
                Turn::Used => self.read_car(core),
                Turn::Parked => return,
                Turn::None => break,
            }
        }
        self.feed(core);
    }

    /// The CAR's next section, when its verdict came: it must be the block
    /// needed next.
    fn car_verdicts(&mut self, core: &mut Core) -> Turn {
        let Some(c) = self.car.as_mut() else {
            return Turn::None;
        };
        let Some(judged) = c.verdicts.remove(&c.done) else {
            return Turn::None;
        };
        c.done += 1;
        c.pending = c
            .pending
            .saturating_sub(judged.cid.len() + judged.block.len() + SECTION_COST);
        if let Err(r) = judged.verdict {
            judged.release(core);
            self.end(core, refusal(r));
            return Turn::Used;
        }
        let same = self.needs.front().is_some_and(|front| {
            match (ipfs_cid::parse(&judged.cid), ipfs_cid::parse(&front.cid)) {
                (Some(a), Some(b)) => a.same_block(&b),
                _ => false,
            }
        });
        let need = if same { self.take_need() } else { None };
        let Some(need) = need else {
            // Not the block the walk needs next: the CAR stops being
            // useful, and the rest comes as raw blocks.
            judged.release(core);
            self.close_car(core);
            self.raw_only = true;
            return Turn::Used;
        };
        // The section's CID and its job's structures are done with: the
        // block is used as a raw block is, in the room it holds, its
        // buffer exactly its bytes ([`Walk::push_frames`]).
        let Judged {
            cid, block, cost, ..
        } = judged;
        cid.release(core);
        cost.release(core);
        let block = block.remake(core, |block| block);
        match self.consume(core, &need, &block) {
            Err(Halt::Wait) => {
                // The block, verified, waits for room as a raw block does.
                self.park(need, Some(block));
                return Turn::Parked;
            }
            Err(Halt::Fail(f)) => {
                block.release(core);
                need.cid.release(core);
                self.end(core, f);
                return Turn::Used;
            }
            Ok(()) => {}
        }
        block.release(core);
        need.cid.release(core);
        Turn::Used
    }

    /// Asks for what the walk needs: a CAR, or raw blocks.
    fn feed(&mut self, core: &mut Core) {
        if !matches!(self.stage, Stage::Dag) || self.over(core) {
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
        // The needs to ask for, by their place in the queue, which nothing
        // here moves.
        let mut pending = [0usize; MAX_RAW_PIECES];
        let mut count = 0;
        for (at, n) in self.needs.iter().enumerate() {
            if count == MAX_RAW_PIECES {
                break;
            }
            if !self.raw.contains_key(&n.seq)
                && !self.arrived.contains_key(&n.seq)
                && ipfs_cid::parse(&n.cid).is_some_and(|c| c.hash != IDENTITY)
            {
                pending[count] = at;
                count += 1;
            }
        }
        // Each block copies body out when it is used, in room held then: a
        // block asked for past the front leaves room for the largest copy
        // of those out, so the blocks asked ahead never take the room the
        // front needs to be used.
        let mut copies = self.copy_out();
        for &at in &pending[..count] {
            if self.raw.len() >= MAX_RAW_PIECES {
                break;
            }
            let need = &self.needs[at];
            let (seq, cid_len, exact) = (need.seq, need.cid.len(), block_len(need).is_some());
            let room = block_room(need);
            let copy = self.copy_estimate(need, room);
            let first = at == 0;
            let ahead = if first { 0 } else { copies.max(copy) };
            if !core.fits(room + cid_len + super::STREAM_WINDOW + ahead) {
                // Room comes back as blocks, jobs and cancelled pieces end
                // and as the body is read; with none of them left, it never
                // will.
                if first && !self.room_returns(core) {
                    return self.end(core, Failure::Memory);
                }
                break;
            }
            let path = format!("/ipfs/{}?format=raw", display(&self.needs[at].cid));
            let headers = vec![("accept".to_owned(), RAW_ACCEPT.to_owned())];
            let Some(id) = core.fetch(
                Tag::Raw(seq),
                path,
                headers,
                Ask::Stream(Some(fc_ipfs::block::MAX_BLOCK)),
            ) else {
                break;
            };
            // Within the room just checked.
            let state = Raw::Reading {
                buf: Charged::new(core, Vec::new(), room),
                cid: Charged::new(core, (), cid_len),
            };
            self.raw.insert(seq, RawPiece { id, exact, state });
            copies = copies.max(copy);
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
            What::Path(0) => format!("/ipfs/{}{}", self.root_text.as_str(), self.car_path()),
            What::Index => format!("/ipfs/{}", display(&front.cid)),
            // A CAR ended before the walk did: raw from here.
            _ => {
                self.raw_only = true;
                return self.feed(core);
            }
        };
        if !core.fits(CAR_ROOM + STREAM_WINDOW + super::MAX_FRAME) {
            self.raw_only = true;
            return self.feed(core);
        }
        let mut path = format!("{target}?format=car&dag-scope=entity");
        if let Some(bytes) = self.entity_bytes(core.head_only) {
            path.push_str("&entity-bytes=");
            path.push_str(&bytes);
        }
        let headers = vec![("accept".to_owned(), CAR_ACCEPT.to_owned())];
        let Some(id) = core.fetch(Tag::Car, path, headers, Ask::Stashed) else {
            self.raw_only = true;
            return self.feed(core);
        };
        self.car = Some(CarStream {
            finished: false,
            id,
            reader: car::Reader::new(),
            // Within the room just checked.
            room: Charged::new(core, (), CAR_ROOM),
            headed: false,
            open: true,
            stash: Stash::default(),
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
            let p = self.raw_path.as_str();
            return if p.is_empty() {
                String::new()
            } else {
                format!("/{p}")
            };
        }
        let mut out = String::new();
        for s in self.segments.iter() {
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
        let early = self
            .file
            .as_ref()
            .filter(|f| !f.headed)
            .map(|f| f.early.len());
        if let Some(n) = early {
            // A file shorter than its sniff: the type from what it has, and
            // its bytes copied out within room held for them.
            let room = match self.reserve(core, n) {
                Ok(room) => room,
                Err(Halt::Wait) => return,
                Err(Halt::Fail(f)) => return self.end(core, f),
            };
            self.hold_copy(core, room);
            self.head_file(core);
            self.drop_copy(core);
        }
        if self.over(core) {
            return;
        }
        self.answer(core, Answer::Finish);
    }

    /// A block the walk needed, checked, in its turn.
    fn consume(&mut self, core: &mut Core, need: &Taken, block: &[u8]) -> Result<(), Halt> {
        match need.what {
            What::Path(seg) => self.node(core, seg, &need.cid, block),
            What::PathShard { seg, level } => self.path_shard(core, seg, level, block),
            What::EntityShard { level } => self.entity_shard(core, level, &need.cid, block),
            What::Index => self.index(core, &need.cid, block),
            What::File { start, len, depth } => {
                self.file_node(core, &need.cid, block, start, len, depth)
            }
        }
    }

    /// The node reached after `seg` segments.
    fn node(&mut self, core: &mut Core, seg: usize, cid: &[u8], block: &[u8]) -> Result<(), Halt> {
        let Some(c) = ipfs_cid::parse(cid) else {
            return Err(Failure::VerificationFailed.into());
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
            match data.kind {
                Kind::Directory => {
                    let name = self.segments[seg].as_str();
                    match node.links().find(|l| l.name == Some(name)) {
                        Some(link) => self.push_first(core, link.cid.bytes, What::Path(seg + 1))?,
                        None => self.page(core, 404, "not found"),
                    }
                }
                Kind::HamtShard => {
                    self.hamt_step(core, seg, 0, &node, data.data.unwrap_or(&[]))?;
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
                    return self.push_first(core, link.cid.bytes, What::Index);
                }
                // The entries, borrowed from the block: their slots held
                // before they are taken.
                let named = |l: &dagpb::Link<'_>| l.name.is_some_and(|n| !n.is_empty());
                let n = node.links().filter(named).count();
                let held = n.saturating_mul(std::mem::size_of::<gateway::Entry<'_>>());
                let room = self.reserve(core, held)?;
                let mut entries = room.map(|()| Vec::with_capacity(n));
                for (at, l) in node.links().enumerate() {
                    if let Some(name) = l.name.filter(|n| !n.is_empty()) {
                        entries.get_mut().push(gateway::Entry {
                            name: Cow::Borrowed(name),
                            size: l.tsize,
                            at,
                        });
                    }
                }
                self.listing(core, entries)
            }
            Kind::HamtShard => {
                // The root's CID, and the shard's with its block.
                let room = self.reserve(core, block.len() + 2 * cid.len() + MAP_ENTRY)?;
                let h = room.remake(core, |()| {
                    let mut h = Hamt {
                        root: cid.to_vec(),
                        ..Hamt::default()
                    };
                    h.shards.insert(cid.to_vec(), block.to_vec());
                    h
                });
                if let Some(old) = self.hamt.replace(h) {
                    old.release(core);
                }
                let pushed = self.push_shards(core, &node, 1);
                if pushed == Err(Halt::Wait) {
                    // Built again when the block is used again.
                    if let Some(h) = self.hamt.take() {
                        h.release(core);
                    }
                }
                pushed
            }
            Kind::Symlink | Kind::Metadata => {
                self.unsupported(core, data.kind);
                Ok(())
            }
        }
    }

    fn unsupported(&mut self, core: &mut Core, kind: Kind) {
        let detail = if kind == Kind::Symlink {
            "unixfs error: unsupported unixfs node type 4"
        } else {
            "unixfs error: unsupported unixfs node type 3"
        };
        self.page(core, 502, detail);
    }

    /// A shard's sub-shards (links named by the bucket's two digits alone),
    /// in link order, ahead of the rest: each read whole for the listing.
    fn push_shards(
        &mut self,
        core: &mut Core,
        node: &dagpb::Node<'_>,
        level: usize,
    ) -> Result<(), Halt> {
        let sub = |l: &dagpb::Link<'_>| l.name.is_some_and(|n| n.len() == 2);
        let (mut n, mut cids) = (0, 0);
        for l in node.links().filter(sub) {
            n += 1;
            cids += l.cid.bytes.len();
        }
        let mut room = self.needs_room(core, n, cids)?;
        for l in node.links().filter(sub) {
            self.add_need(&mut room, l.cid.bytes, What::EntityShard { level });
        }
        room.release(core);
        self.needs.get_mut().rotate_right(n);
        Ok(())
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

    /// Segment `seg`'s next step in the HAMT shard `node`, at `level`.
    fn hamt_step(
        &mut self,
        core: &mut Core,
        seg: usize,
        level: usize,
        node: &dagpb::Node<'_>,
        bitfield: &[u8],
    ) -> Result<(), Halt> {
        if level >= hamt::MAX_LEVELS {
            return Err(Failure::Unverifiable.into());
        }
        let step = hamt::step(node, bitfield, &self.segments[seg], level);
        match step {
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
                Ok(())
            }
        }
    }

    fn path_shard(
        &mut self,
        core: &mut Core,
        seg: usize,
        level: usize,
        block: &[u8],
    ) -> Result<(), Halt> {
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
        self.hamt_step(core, seg, level, &node, data.data.unwrap_or(&[]))
    }

    fn entity_shard(
        &mut self,
        core: &mut Core,
        level: usize,
        cid: &[u8],
        block: &[u8],
    ) -> Result<(), Halt> {
        if level >= hamt::MAX_LEVELS {
            return Err(Failure::Unverifiable.into());
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
        let Some(h) = self.hamt.as_ref() else {
            return Err(Failure::Unverifiable.into());
        };
        // A shard linked twice is held once; so is a shard whose block
        // waited for room after it was taken in.
        if !h.shards.contains_key(cid) {
            let room = self.reserve(core, block.len() + cid.len() + MAP_ENTRY)?;
            match self.hamt.as_mut() {
                Some(h) => {
                    h.absorb(room);
                    h.change(core, |h| {
                        h.shards.insert(cid.to_vec(), block.to_vec());
                    });
                }
                None => room.release(core),
            }
        }
        self.push_shards(core, &node, level + 1)
    }

    /// Every shard is in: `index.html` by its hash, or the listing. While
    /// it waits for room, the shards are kept for the next try.
    fn hamt_done(&mut self, core: &mut Core) -> Result<(), Halt> {
        let Some(h) = self.hamt.take() else {
            return Ok(());
        };
        let mut at: &[u8] = &h.root;
        let mut found = None;
        for level in 0..hamt::MAX_LEVELS {
            let Some(block) = h.shards.get(at) else {
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
                    found = Some(link.cid.bytes);
                    break;
                }
                Step::Shard(link) => at = link.cid.bytes,
                Step::Absent => break,
            }
        }
        if let Some(cid) = found {
            if let Err(e) = self.push_first(core, cid, What::Index) {
                self.hamt = Some(h);
                return Err(e);
            }
            h.release(core);
            return Ok(());
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
        let room = match self.reserve(core, held) {
            Ok(room) => room,
            Err(e) => {
                self.hamt = Some(h);
                return Err(e);
            }
        };
        let mut entries = room.map(|()| Vec::with_capacity(n));
        Self::hamt_entries(&h.shards, &h.root, 0, &mut |name, size| {
            let name = match std::str::from_utf8(name) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => Cow::Owned(lossy(name)),
            };
            let at = entries.len();
            entries.get_mut().push(gateway::Entry { name, size, at });
        });
        if let Err(e) = self.listing(core, entries) {
            self.hamt = Some(h);
            return Err(e);
        }
        h.release(core);
        Ok(())
    }

    /// Room for path strings of at most `bytes` in `n` segments, held
    /// before they are built.
    fn path_room(&mut self, core: &mut Core, n: usize, bytes: usize) -> Result<Charged<()>, Halt> {
        let need = bytes.saturating_add(n.saturating_mul(std::mem::size_of::<String>()));
        self.reserve(core, need)
    }

    /// The served path: the walked segments, and the index document's name
    /// for a directory.
    fn serve_path(&mut self, core: &mut Core, last: Option<&str>) -> Result<(), Halt> {
        let n = self.segments.len() + usize::from(last.is_some());
        let bytes = self.segments.iter().map(String::len).sum::<usize>() + last.map_or(0, str::len);
        let room = self.path_room(core, n, bytes)?;
        let segments = &self.segments;
        let served = room.remake(core, |()| {
            let mut served = Vec::with_capacity(n);
            served.extend(segments.iter().cloned());
            served.extend(last.map(str::to_owned));
            served
        });
        put(core, &mut self.served, served);
        Ok(())
    }

    fn index(&mut self, core: &mut Core, cid: &[u8], block: &[u8]) -> Result<(), Halt> {
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
    /// charged as they were taken. Its title and links' base are made
    /// within room for them; the page is counted, its room and its
    /// headers' held, then written into a buffer of exactly that length.
    /// While it waits for room, the entries go, made again on the next try.
    fn listing(
        &mut self,
        core: &mut Core,
        mut entries: Charged<Vec<gateway::Entry<'_>>>,
    ) -> Result<(), Halt> {
        if self.asked.range.is_some() {
            entries.release(core);
            self.page(
                core,
                400,
                "Range requests are not supported for directory listings",
            );
            return Ok(());
        }
        let names = match self.reserve(core, self.names_room()) {
            Ok(room) => room.remake(core, |()| self.title_and_base()),
            Err(e) => {
                entries.release(core);
                return Err(e);
            }
        };
        gateway::sort_listing(entries.get_mut());
        let len = gateway::listing_len(&names.0, &names.1, &entries);
        let mut room = match self.reserve(core, len.saturating_add(HEAD_ROOM)) {
            Ok(room) => room,
            Err(e) => {
                entries.release(core);
                names.release(core);
                return Err(e);
            }
        };
        let (headers, body) = gateway::listing(&names.0, &names.1, &entries, len);
        let body = room.split(len).map(|()| body);
        entries.release(core);
        names.release(core);
        self.answer(
            core,
            Answer::Head {
                status: 200,
                headers,
                room,
                body: Some(body),
            },
        );
        Ok(())
    }

    /// Room for a listing's title and its links' base while they are made
    /// ([`Walk::title_and_base`]): the root's text or the name, and the
    /// request's path, decoded and percent-encoded, each string at most
    /// twice its length as it grows, beside the segments they are made
    /// from.
    fn names_room(&self) -> usize {
        let p = self.raw_path.len();
        let text = self.root_text.len() + self.ipns.as_ref().map_or(0, |n| n.len());
        16 * (p + text + 16) + 2 * (p + 2) * std::mem::size_of::<String>()
    }

    /// A listing's title, the request's path decoded below its root or
    /// name, and the base its links are written below.
    fn title_and_base(&self) -> (String, String) {
        match &self.ipns {
            None => {
                let shown = self.shown_path();
                let title = if shown.is_empty() {
                    format!("/ipfs/{}", self.root_text.as_str())
                } else {
                    format!("/ipfs/{}/{shown}", self.root_text.as_str())
                };
                let enc = gateway::encode_path(&self.segments[..]);
                let base = if enc.is_empty() {
                    format!("/ipfs/{}", self.root_text.as_str())
                } else {
                    format!("/ipfs/{}/{enc}", self.root_text.as_str())
                };
                (title, base)
            }
            Some(name) => {
                let name = name.as_str();
                let shown = self.shown_path();
                let title = if shown.is_empty() {
                    format!("/ipns/{name}")
                } else {
                    format!("/ipns/{name}/{shown}")
                };
                let mut segs = vec![name.to_owned()];
                segs.extend(self.rest_segments());
                (title, format!("/ipns/{}", gateway::encode_path(&segs)))
            }
        }
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
        segments(&format!("/{}", self.raw_path.as_str()))
            .unwrap_or_default()
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect()
    }

    // The file.

    /// The file's root is in: the range, the tag and the conditional, then
    /// its content. The tag, the type by extension and room for the head's
    /// headers are reserved before they are made, and the file keeps them.
    fn start_file(
        &mut self,
        core: &mut Core,
        block: &[u8],
        node: Option<(&dagpb::Node<'_>, &unixfs::Data<'_>)>,
    ) -> Result<(), Halt> {
        let len = match node {
            None => block.len() as u64,
            Some((_, d)) => d.filesize.ok_or(Failure::Malformed)?,
        };
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
        let tag_room = etag_room(&self.root_text, &self.served);
        let mut room = self.reserve(core, 2 * (tag_room + MIME_ROOM) + HEAD_ROOM)?;
        let (root_text, served) = (&self.root_text, &self.served);
        let etag = room
            .split(tag_room)
            .remake(core, |()| gateway::etag(root_text, &served[..], len));
        let mime = room
            .split(MIME_ROOM)
            .remake(core, |()| gateway::type_by_extension(&served[..]));
        // The head's headers copy the tag and the type.
        let head = room.split(HEAD_ROOM + etag.cost() + mime.cost());
        room.release(core);
        if range.is_none()
            && self
                .asked
                .if_none_match
                .as_deref()
                .is_some_and(|v| gateway::if_none_match(v, &etag))
        {
            let headers = gateway::not_modified(&etag, self.cache);
            etag.release(core);
            mime.release(core);
            self.answer(
                core,
                Answer::Head {
                    status: 304,
                    headers,
                    room: head,
                    body: None,
                },
            );
            return Ok(());
        }
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
        let file = File {
            a,
            b,
            len,
            sniff,
            headed: false,
            early: Charged::nothing(core),
            mime,
            etag,
            head: Some(head),
            range,
        };
        if let Some(old) = self.file.replace(file) {
            old.release(core);
        }
        // A HEAD, or an empty file, whose type isn't sniffed: the head is
        // all there is. Otherwise it goes once the content's room is held
        // ([`Walk::content`]), or with the bytes its type is sniffed from.
        if sniff.is_none() && (core.head_only || len == 0) {
            self.head_file(core);
            return Ok(());
        }
        // The needs below the root are the file's only: what the path's
        // CAR or the index's carries next.
        let r = self.content(core, block, node, 0, len, 0);
        if r == Err(Halt::Wait) {
            // Started again when the block is used again.
            if let Some(f) = self.file.take() {
                f.release(core);
            }
        }
        r
    }

    /// The head of the file being served, its headers made within the
    /// room the file kept for them. For a HEAD it is the answer.
    fn head_file(&mut self, core: &mut Core) {
        let Some(f) = self.file.as_mut() else {
            return;
        };
        if f.headed {
            return;
        }
        f.headed = true;
        let headers = {
            let sniffed;
            let mime = match f.mime.as_deref() {
                Some(m) => m,
                None => {
                    sniffed = gateway::sniffed(&f.early);
                    &sniffed
                }
            };
            match f.range {
                Some((s, e)) => gateway::partial(mime, s, e, f.len, &f.etag, self.cache),
                None => gateway::whole(mime, f.len, &f.etag, self.cache),
            }
        };
        let status = if f.range.is_some() { 206 } else { 200 };
        let early = std::mem::replace(&mut f.early, Charged::nothing(core));
        let room = f.head.take();
        let room = room.unwrap_or_else(|| Charged::new(core, (), 0));
        if core.head_only {
            // A HEAD: nothing past the head.
            early.release(core);
            self.answer(
                core,
                Answer::Head {
                    status,
                    headers,
                    room,
                    body: None,
                },
            );
            return;
        }
        core.head_charged(status, headers, self.label, room);
        self.release(core, &early, 0);
        early.release(core);
        if self.file.as_ref().is_some_and(|f| f.len == 0) {
            self.answer(core, Answer::Finish);
        }
    }

    /// A file node's content: its own data at `start`, then its children
    /// within the body, read in turn. Room for the data's copy into the
    /// body and for the children is held first, before the head or any of
    /// its bytes go out, so the block can wait for it whole.
    fn content(
        &mut self,
        core: &mut Core,
        block: &[u8],
        node: Option<(&dagpb::Node<'_>, &unixfs::Data<'_>)>,
        start: u64,
        len: u64,
        depth: usize,
    ) -> Result<(), Halt> {
        let inline = match node {
            // A raw leaf: the block is the content, and its length is the
            // one its parent declared (deviation `unixfs-sizes`).
            None if block.len() as u64 != len => return Err(Failure::Malformed.into()),
            None => block,
            Some((_, data))
                if !matches!(data.kind, Kind::File | Kind::Raw) || data.filesize != Some(len) =>
            {
                return Err(Failure::Malformed.into());
            }
            Some((_, data)) => data.data.unwrap_or(&[]),
        };
        let Some(f) = self.file.as_ref() else {
            return Ok(());
        };
        let (a, b) = (f.a, f.b);
        let first = start + inline.len() as u64;
        // The children within the body, each with its offset: counted and
        // their room held, then queued ahead of what follows the node.
        let within = || {
            let mut at = first;
            node.into_iter()
                .flat_map(|(node, data)| node.links().zip(data.blocksizes()))
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
            return Err(Failure::Unverifiable.into());
        }
        let copy = self.copy_bound(start, inline.len());
        let room = self.reserve(core, copy)?;
        self.hold_copy(core, room);
        let mut room = match self.needs_room(core, n, cids) {
            Ok(room) => room,
            Err(e) => {
                self.drop_copy(core);
                return Err(e);
            }
        };
        // A file whose type isn't sniffed has its head now.
        if self
            .file
            .as_ref()
            .is_some_and(|f| !f.headed && f.sniff.is_none())
        {
            self.head_file(core);
        }
        if !self.over(core) {
            self.emit(core, start, inline);
        }
        self.drop_copy(core);
        if self.over(core) || self.file.is_none() {
            room.release(core);
            return Ok(());
        }
        for (link, child, size) in within() {
            self.add_need(
                &mut room,
                link.cid.bytes,
                What::File {
                    start: child,
                    len: size,
                    depth: depth + 1,
                },
            );
        }
        room.release(core);
        self.needs.get_mut().rotate_right(n);
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
    ) -> Result<(), Halt> {
        if ipfs_cid::parse(cid).is_some_and(|c| c.codec == ipfs_cid::RAW) {
            return self.content(core, block, None, start, len, depth);
        }
        let node = dagpb::decode(block).map_err(refusal)?;
        let data = unixfs::decode(&node).map_err(refusal)?;
        self.content(core, block, Some((&node, &data)), start, len, depth)
    }

    /// Content at `start`: before the head, what the sniff waits for; after
    /// it, what the body's range holds. Each copy is within the room held
    /// for the block's ([`Walk::draw`]).
    fn emit(&mut self, core: &mut Core, start: u64, bytes: &[u8]) {
        let Some(f) = self.file.as_ref() else {
            return;
        };
        if f.headed {
            return self.release(core, bytes, start);
        }
        // Only bytes 0 to the sniff's end are kept for the type, as
        // `GatewayCore` reads no more; the head goes once they're in.
        let end = f.sniff.unwrap_or(0);
        if start <= end {
            let keep = usize::try_from(end + 1 - start)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            let room = self.draw(core, keep);
            match self.file.as_mut() {
                Some(f) => {
                    f.early.absorb(room);
                    f.early.change(core, |early| {
                        early.reserve_exact(keep);
                        early.extend_from_slice(&bytes[..keep]);
                    });
                }
                None => room.release(core),
            }
        }
        let past = end + 1;
        if start + bytes.len() as u64 >= past {
            self.head_file(core);
            // The rest of this slice, past the sniffed bytes.
            if self.file.as_ref().is_some_and(|f| f.headed) && !self.over(core) {
                let from = usize::try_from(past.saturating_sub(start)).unwrap_or(usize::MAX);
                if let Some(tail) = bytes.get(from..).filter(|t| !t.is_empty()) {
                    self.release(core, tail, start.max(past));
                }
            }
        }
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
        let room = self.draw(core, part.len());
        core.body_charged(room.map(|()| part.to_vec()), None);
    }

    // The sources' events.

    fn car_data(&mut self, core: &mut Core, bytes: Vec<u8>) {
        let Some(c) = self.car.as_mut() else {
            return;
        };
        // Copied into the stream's buffer, and the frame goes.
        c.stash.push(&bytes);
        drop(bytes);
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
        match Self::push_frames(c, &mut self.sections, core) {
            Ok(Read::On) => {}
            // The CAR is a shortcut: without room to read it on, the rest
            // comes as raw blocks, and only a raw block that can't fit
            // either ends the walk for its memory.
            Ok(Read::GiveWay) => {
                self.close_car(core);
                self.raw_only = true;
                return self.pump(core);
            }
            Err(failure) => {
                Self::break_car(c, core, failure);
                return self.car_settled(core);
            }
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
        c.stash.free(core);
        c.ended = true;
        c.broken.get_or_insert(failure);
    }

    /// Frames into the reader while the body the page hasn't read has room
    /// (any once the stream has ended: nothing is held back then), as much
    /// of each as can complete no more sections than may still wait, nor
    /// more than [`PUSH_SECTIONS`] at once, each counted with its job's
    /// structures; and only while the request has room for what those
    /// bytes can complete (the section being read, the bytes themselves
    /// and the vector the sections come in). Without that room, and
    /// nothing that will give it back, the CAR gives way to raw blocks.
    fn push_frames(
        c: &mut CarStream,
        sections: &mut Charged<()>,
        core: &mut Core,
    ) -> Result<Read, Failure> {
        while c.finished || core.awaiting() < QUEUE_LIMIT {
            let starts = PENDING_LIMIT.saturating_sub(c.pending) / SECTION_COST;
            if starts == 0 {
                // The sections waiting free room as their verdicts are used.
                return Ok(Read::On);
            }
            let frame = c.stash.front();
            if frame.is_empty() {
                return Ok(Read::On);
            }
            // The item being read completes with the bytes it wants; each
            // further section takes at least MIN_SECTION.
            let starts = starts.min(PUSH_SECTIONS);
            let wanting = c.reader.wanting();
            let further = if wanting > 0 { starts - 1 } else { starts };
            let most = wanting
                .saturating_add(further.saturating_mul(car::MIN_SECTION))
                .saturating_add(car::MIN_SECTION - 1);
            let take = frame.len().min(most);
            if !core.fits(c.reader.holding() + take + SECTIONS_ROOM) {
                // Room comes back as sections are used and the body is
                // read; with neither waiting, it never will.
                if c.pending == 0 && core.awaiting() == 0 {
                    return Ok(Read::GiveWay);
                }
                return Ok(Read::On);
            }
            // Within the room just checked.
            let list = Charged::new(core, (), SECTIONS_ROOM);
            let pushed = c.reader.push(&frame[..take]);
            // The bytes are the reader's now, within its room; their place
            // in the window is main's again.
            c.stash.consume(core, take);
            if c.open {
                core.consumed(c.id, take);
            }
            let mut give_way = false;
            for section in pushed.sections {
                // The section's own buffer, the CID moved out of its front.
                let (mut block, cid_len) = section.into_parts();
                let cid = block.drain(..cid_len).collect::<Vec<u8>>();
                let size = cid.len() + block.len();
                // The section's bytes leave the reader for the job, which
                // holds them beside the reader's room, with its own
                // structures. Without room for both, the section, out of
                // the reader, can't wait: it and the rest come as raw
                // blocks.
                let Some(mut room) = Charged::room(core, size + SECTION_COST) else {
                    give_way = true;
                    break;
                };
                // The buffer gives the CID's bytes back, shrunk in place, so
                // the block holds what a raw block's exact buffer does.
                block.shrink_to_fit();
                let n = c.sent;
                c.sent += 1;
                c.pending += size + SECTION_COST;
                let work = room.split(size).map(|()| Work::Block { cid, block });
                core.hash_charged(Tag::Section(n), work);
                sections.absorb(room);
            }
            list.release(core);
            if give_way {
                return Ok(Read::GiveWay);
            }
            if let Some(r) = pushed.error {
                return Err(refusal(r));
            }
        }
        Ok(Read::On)
    }

    fn car_end(&mut self, core: &mut Core) {
        let Some(c) = self.car.as_mut() else {
            return core.window_done();
        };
        c.open = false;
        // What it stashed is read first, in the window kept for it.
        c.finished = true;
        c.stash.keep(core);
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
            return;
        };
        let exact = r.exact;
        let id = r.id;
        let Raw::Reading { buf, .. } = &mut r.state else {
            return;
        };
        let n = bytes.len();
        let have = buf.len();
        let len = have + n;
        if len > buf.capacity() {
            // The buffer moves to its next size within the room held for it
            // and the piece's window, which holds nothing past main's frame
            // (its bytes are credited as they are copied). What the move
            // needs past them is held while it is made, and bytes past the
            // room (a node longer than a leaf's entry) keep their room.
            let next = next_size(buf, exact, len);
            let grow = next.saturating_sub(buf.cost());
            let over =
                (buf.capacity() + next + n).saturating_sub(buf.cost() + grow + STREAM_WINDOW);
            let Some(mut room) = Charged::room(core, grow + over) else {
                return self.end(core, Failure::Memory);
            };
            let over = room.split(over);
            buf.absorb(room);
            buf.get_mut().reserve_exact(next - have);
            over.release(core);
        }
        buf.get_mut().extend_from_slice(&bytes);
        drop(bytes);
        core.consumed(id, n);
    }

    fn raw_end(&mut self, core: &mut Core, seq: u64) {
        let Some(at) = self.needs.iter().position(|n| n.seq == seq) else {
            if let Some(r) = self.raw.remove(&seq) {
                r.release(core);
            }
            return core.window_done();
        };
        let Some(r) = self.raw.get_mut(&seq) else {
            return core.window_done();
        };
        let Raw::Reading { .. } = r.state else {
            return core.window_done();
        };
        let Raw::Reading { buf, cid } = std::mem::replace(&mut r.state, Raw::Hashing) else {
            return core.window_done();
        };
        // A buffer longer than its block (a node of unknown length) is cut
        // to it: a copy, at most, beside the buffer, made within its room
        // and the window the block came through, which the walk holds
        // until this end is done, and room held past them. Without that
        // room the buffer is kept whole, and its room with it, until it
        // goes. Room never made into the buffer goes.
        let len = buf.len();
        let over = if buf.capacity() > len {
            let over = (buf.capacity() + len).saturating_sub(buf.cost() + STREAM_WINDOW);
            Charged::room(core, over)
        } else {
            None
        };
        let cut = over.is_some();
        let block = buf.remake(core, |mut b| {
            if cut {
                b.shrink_to_fit();
            }
            b
        });
        if let Some(over) = over {
            over.release(core);
        }
        core.window_done();
        // The block, its whole buffer, and a copy of its CID are the job's
        // now, which counts them all.
        let cid = cid.map(|()| self.needs[at].cid.to_vec());
        let work = cid
            .join(block)
            .map(|(cid, block)| Work::Block { cid, block });
        core.hash_charged(Tag::Raw(seq), work);
    }

    fn whole_record(&mut self, core: &mut Core, status: u16, body: Bytes) {
        let Stage::Record { name, .. } = &self.stage else {
            return body.release(core);
        };
        if status != 200 {
            body.release(core);
            return self.end(core, Failure::Status(status));
        }
        // The name's CID beside the record, for its job, and room for what
        // the job's result holds: the record's value and validity, each a
        // part of it. Nothing else is out: room that doesn't fit never
        // will.
        let cid = match charged_cid(core, name, ipfs_cid::from_key_text) {
            Ok(Some(cid)) => cid,
            Ok(None) => {
                body.release(core);
                return self.end(core, Failure::Unverifiable);
            }
            Err(f) => {
                body.release(core);
                return self.end(core, f);
            }
        };
        let Some(room) = Charged::room(core, body.len()) else {
            cid.release(core);
            body.release(core);
            return self.end(core, Failure::Memory);
        };
        if let Stage::Record { result, .. } = &mut self.stage
            && let Some(old) = result.replace(room)
        {
            old.release(core);
        }
        let now = self.asked.now;
        let work = cid
            .join(body)
            .map(|(name, record)| Work::Record { name, record, now });
        core.hash_charged(Tag::Record, work);
    }

    /// The record's verdict: its value waits for the partition's floor,
    /// in the room held for it, and its name goes to main with the floor's
    /// question.
    fn record_hashed(
        &mut self,
        core: &mut Core,
        result: Result<fc_ipfs::ipns::Record, BlockRefusal>,
        name: Bytes,
        record: Bytes,
    ) {
        let room = match &mut self.stage {
            Stage::Record { result, .. } => result.take(),
            _ => None,
        };
        let Stage::Record { hop, .. } = self.stage else {
            name.release(core);
            record.release(core);
            if let Some(room) = room {
                room.release(core);
            }
            return;
        };
        let (value, sequence, until) = match result {
            Ok(r) => {
                let fc_ipfs::ipns::Record {
                    value,
                    sequence,
                    validity,
                    ..
                } = r;
                let until = fc_ipfs::rfc3339::parse(&validity);
                drop(validity);
                (value, sequence, until)
            }
            Err(e) => {
                name.release(core);
                record.release(core);
                if let Some(room) = room {
                    room.release(core);
                }
                return self.end(core, refusal(e));
            }
        };
        record.release(core);
        let value = match room {
            Some(room) => room.remake(core, |()| value),
            None => Charged::measured(core, value),
        };
        let Some((secs, nanos)) = until else {
            value.release(core);
            name.release(core);
            return self.end(core, Failure::Unverifiable);
        };
        // Held to the partition's floor before its value is followed (0009,
        // IPNS and DNSLink).
        let valid_until = secs.saturating_add(i64::from(nanos > 0));
        if let Stage::Record { name, result, .. } =
            std::mem::replace(&mut self.stage, Stage::Floor { hop, value })
        {
            name.release(core);
            if let Some(r) = result {
                r.release(core);
            }
        }
        name.hand_over(core, |core, name| {
            core.ask_floor(name, sequence, valid_until);
        });
    }
}

/// The machine's inputs, each value under the charge the machine took for
/// it as it came. Each ends with the walk's answer, if it has one, given
/// to the core ([`Walk::conclude`]).
impl super::Events<Tag> for Walk {
    fn audit(&self, core: &mut Core) {
        core.audit_charged();
    }

    fn whole(
        &mut self,
        core: &mut Core,
        tag: Tag,
        status: u16,
        _headers: &[(String, String)],
        body: Vec<u8>,
    ) {
        let n = body.len();
        let body = Charged::arrived(core, body, n);
        match tag {
            Tag::Record => self.whole_record(core, status, body),
            _ => body.release(core),
        }
        self.conclude(core);
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
                if let Some(c) = self.car.as_mut() {
                    c.headed = true;
                    let typed = header(headers, "content-type").is_some_and(car_type_ok);
                    if status == 200 && typed {
                    } else if status == 200 {
                        // Another type or parameters (`dups=n` among them):
                        // not read; the walk's blocks come raw.
                        self.close_car(core);
                        self.raw_only = true;
                        self.pump(core);
                    } else {
                        // Any other status is the gateway's final answer.
                        self.end(core, Failure::Status(status));
                    }
                }
            }
            Tag::Raw(seq) if status != 200 => {
                if let Some(r) = self.raw.remove(&seq) {
                    let id = r.id;
                    r.release(core);
                    core.cancel_piece(id);
                }
                self.end(core, Failure::Status(status));
            }
            _ => {}
        }
        self.conclude(core);
    }

    fn stream_data(&mut self, core: &mut Core, tag: Tag, _id: PieceId, bytes: Vec<u8>) {
        match tag {
            Tag::Car => self.car_data(core, bytes),
            Tag::Raw(seq) => self.raw_data(core, seq, bytes),
            _ => drop(bytes),
        }
        self.conclude(core);
    }

    fn floor(&mut self, core: &mut Core, check: crate::store::FloorCheck) -> bool {
        let Stage::Floor { .. } = self.stage else {
            return false;
        };
        let Stage::Floor { hop, value } = std::mem::replace(&mut self.stage, Stage::Done) else {
            return false;
        };
        match check {
            crate::store::FloorCheck::Refused => self.end(core, Failure::VerificationFailed),
            // `GatewayCore` resolves a fourth name, then refuses whatever it
            // names.
            crate::store::FloorCheck::Accepted if hop > MAX_RESOLUTIONS => {
                self.page(core, 400, "dnslink recursion limit exceeded");
            }
            crate::store::FloorCheck::Accepted => self.record_value(core, &value, hop),
        }
        value.release(core);
        self.conclude(core);
        true
    }

    fn room(&mut self, core: &mut Core) {
        self.read_car(core);
        self.pump(core);
        self.conclude(core);
    }

    fn stream_end(&mut self, core: &mut Core, tag: Tag, _id: PieceId) {
        match tag {
            Tag::Car => self.car_end(core),
            Tag::Raw(seq) => self.raw_end(core, seq),
            _ => {}
        }
        self.conclude(core);
    }

    fn failed(&mut self, core: &mut Core, tag: Tag, failure: PieceFailure) {
        if let Tag::Raw(seq) = tag {
            if let Some(r) = self.raw.remove(&seq) {
                r.release(core);
            }
            core.window_done();
        }
        match (tag, self.car.as_mut()) {
            (Tag::Car, None) => {
                core.window_done();
                self.end(core, Failure::Piece(failure));
            }
            (Tag::Car, Some(c)) => {
                // The sections it sent before failing are still used, and
                // what it stashed is still read, in the window kept for it.
                c.open = false;
                c.ended = true;
                c.broken = Some(Failure::Piece(failure));
                c.stash.keep(core);
                self.car_settled(core);
            }
            _ => self.end(core, Failure::Piece(failure)),
        }
        self.conclude(core);
    }

    fn hashed(&mut self, core: &mut Core, tag: Tag, verdict: Verdict, work: Work) {
        match (tag, verdict, work) {
            (Tag::Record, Verdict::Record(result), Work::Record { name, record, .. }) => {
                let (n, m) = (name.len(), record.len());
                let name = Charged::arrived(core, name, n);
                let record = Charged::arrived(core, record, m);
                self.record_hashed(core, result, name, record);
            }
            (Tag::Section(n), Verdict::Block(result), Work::Block { cid, block }) => {
                let (c, b) = (cid.len(), block.capacity());
                let cid = Charged::arrived(core, cid, c);
                let block = Charged::arrived(core, block, b);
                let cost = self.sections.split(SECTION_COST);
                let judged = Judged {
                    cid,
                    block,
                    cost,
                    verdict: result,
                };
                match self.car.as_mut() {
                    // The CAR gave way: the section's room, and its job's
                    // structures' room, go to the raw blocks.
                    None => {
                        judged.release(core);
                        self.pump(core);
                    }
                    Some(c) => {
                        c.verdicts.insert(n, judged);
                        self.pump(core);
                        if self.car.is_some() {
                            self.car_settled(core);
                        }
                    }
                }
            }
            (Tag::Raw(seq), Verdict::Block(result), Work::Block { cid, block }) => {
                // The job counted the block's whole buffer, and so does the
                // walk now.
                let (c, b) = (cid.len(), block.capacity());
                Charged::arrived(core, cid, c).release(core);
                let block = Charged::arrived(core, block, b);
                if let Some(r) = self.raw.remove(&seq) {
                    r.release(core);
                }
                match result {
                    Err(r) => {
                        block.release(core);
                        self.end(core, refusal(r));
                    }
                    Ok(()) => {
                        if self.needs.iter().any(|n| n.seq == seq) {
                            self.arrived.insert(seq, block);
                        } else {
                            block.release(core);
                        }
                        self.pump(core);
                    }
                }
            }
            (_, _, work) => {
                let n = work.size();
                Charged::arrived(core, work, n).release(core);
            }
        }
        self.conclude(core);
    }
}
