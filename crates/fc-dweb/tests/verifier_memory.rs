//! The IPFS walk's memory, measured by the allocator (design 0009,
//! Bounds: a request's memory is reserved before it is allocated).
//! Requests whose decoded structure would far exceed their budget (a
//! directory's entries, a HAMT's shards and entries, a file node's
//! children, a listing's page) end `unverifiable` without allocating past
//! it, and those that fit are answered.
//!
//! A counting global allocator caps the process, for each request, at what
//! it held before plus the request's budget plus a small allowance for the
//! driver and the machine's own fixed structures. An allocation past the
//! cap fails, which aborts this test binary ("memory allocation of N bytes
//! failed"). The gateway's answers are built before the cap is set.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::alloc::System;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cap::Cap;
use fc_dweb::verifier::{
    Method, Options, Output, PieceId, REQUEST_BUDGET, STREAM_WINDOW, Verifier,
};
use fc_dweb::{Backend, ContentTrust, Ipfs, Node, ResponseOp, Root, Trust, Verify, retry, timers};
use sha2::Digest;

#[global_allocator]
static ALLOC: Cap<System> = Cap::new(System, usize::MAX);

/// The most the last request reserved at any step.
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// What the driver and the machine's fixed structures may take beside the
/// request's budget.
const SLACK: usize = 256 << 10;
const CAR_TYPE: &str = "application/vnd.ipld.car; version=1; order=dfs; dups=y";
const RAW_TYPE: &str = "application/vnd.ipld.raw";
const UNVERIFIABLE: &str =
    "error 502 This content can't be verified with the external IPFS gateway";

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn field(number: u64, bytes: &[u8], out: &mut Vec<u8>) {
    varint(number << 3 | 2, out);
    varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn field_varint(number: u64, v: u64, out: &mut Vec<u8>) {
    varint(number << 3, out);
    varint(v, out);
}

/// A dag-pb node in canonical form: its links (CID, name, Tsize), then
/// `Data`.
fn pb_node(links: &[(Vec<u8>, String, u64)], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (cid, name, tsize) in links {
        let mut l = Vec::new();
        field(1, cid, &mut l);
        field(2, name.as_bytes(), &mut l);
        field_varint(3, *tsize, &mut l);
        field(2, &l, &mut out);
    }
    field(1, data, &mut out);
    out
}

fn sha256_cid(codec: u8, block: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01, codec, 0x12, 0x20];
    out.extend_from_slice(&sha2::Sha256::digest(block));
    out
}

/// A raw identity CID of `data`.
fn identity(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01, 0x55, 0x00];
    varint(data.len() as u64, &mut out);
    out.extend_from_slice(data);
    out
}

fn text(cid: &[u8]) -> String {
    fc_ipfs::cid::to_text(&fc_ipfs::cid::parse(cid).unwrap())
}

/// A CAR v1 of these blocks, rooted at the first.
fn car(blocks: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let root = &blocks[0].0;
    let mut h = vec![0xa2, 0x65];
    h.extend_from_slice(b"roots");
    h.extend_from_slice(&[0x81, 0xd8, 0x2a, 0x58, (root.len() + 1) as u8, 0x00]);
    h.extend_from_slice(root);
    h.push(0x67);
    h.extend_from_slice(b"version");
    h.push(0x01);
    let mut out = Vec::new();
    varint(h.len() as u64, &mut out);
    out.extend_from_slice(&h);
    for (cid, block) in blocks {
        varint((cid.len() + block.len()) as u64, &mut out);
        out.extend_from_slice(cid);
        out.extend_from_slice(block);
    }
    out
}

fn plan(root: &[u8]) -> Verify {
    let backend = Backend::ipfs(Ipfs::Gateway, true);
    Verify {
        node: Node::Ipfs,
        root: Root::Ipfs(text(root)),
        path: String::new(),
        query: String::new(),
        headers: vec![],
        retry: retry(backend),
        timers: timers(backend),
        response: vec![ResponseOp::StripPageState],
        trust: Trust {
            name: None,
            content: ContentTrust::Verified,
        },
    }
}

struct Stream {
    id: PieceId,
    body: Arc<Vec<u8>>,
    sent: usize,
    credited: usize,
    cancelled: bool,
    done: bool,
}

/// The gateway's answers by path: a CAR, or a raw block.
type World = HashMap<String, Arc<Vec<u8>>>;

/// The request through main, the hashing pool and a page that reads at
/// once, against a gateway that answers from `world`: the head's status,
/// the body's length, and how the request ended. With `slow_pool`, jobs
/// run only once no piece can move: every job the machine asks for waits.
fn drive(v: &mut Verifier, world: &World, slow_pool: bool) -> (Option<u16>, usize, String) {
    let mut jobs = VecDeque::new();
    let mut asked = VecDeque::new();
    let mut streams: Vec<Stream> = Vec::new();
    let (mut head, mut body) = (None, 0);
    loop {
        PEAK.fetch_max(v.reserved(), Ordering::Relaxed);
        while let Some(o) = v.poll() {
            match o {
                Output::Piece(r) => asked.push_back(r),
                Output::CancelPiece(id) => {
                    if let Some(s) = streams.iter_mut().find(|s| s.id == id) {
                        s.cancelled = true;
                    }
                }
                Output::Credit { piece, bytes } => {
                    if let Some(s) = streams.iter_mut().find(|s| s.id == piece) {
                        s.credited += bytes;
                    }
                }
                Output::Hash(job) => jobs.push_back(job),
                Output::Head(h) => head = Some(h.status),
                Output::Body(b) => {
                    body += b.len();
                    let n = b.len();
                    drop(b);
                    v.body_credit(n).unwrap();
                }
                Output::End => return (head, body, "end".to_owned()),
                Output::Error(e) => {
                    return (head, body, format!("error {} {}", e.status, e.message));
                }
                Output::Abort { code, message } => {
                    return (head, body, format!("abort {} {message}", code.as_str()));
                }
                Output::Cancelled => return (head, body, "cancelled".to_owned()),
            }
        }
        if !slow_pool && let Some(job) = jobs.pop_front() {
            v.hashed(job.run()).unwrap();
            continue;
        }
        if let Some(r) = asked.pop_front() {
            let answer = world
                .get(&r.path)
                .unwrap_or_else(|| panic!("{}", r.path))
                .clone();
            let kind = if r.path.ends_with("format=raw") {
                RAW_TYPE
            } else {
                CAR_TYPE
            };
            v.piece_head(
                r.id,
                200,
                vec![("content-type".to_owned(), kind.to_owned())],
            )
            .unwrap();
            streams.push(Stream {
                id: r.id,
                body: answer,
                sent: 0,
                credited: 0,
                cancelled: false,
                done: false,
            });
            continue;
        }
        let mut moved = false;
        for s in streams.iter_mut().filter(|s| !s.done) {
            if s.cancelled || s.sent == s.body.len() {
                v.piece_end(s.id).unwrap();
                s.done = true;
                moved = true;
                break;
            }
            let room = STREAM_WINDOW - (s.sent - s.credited);
            if room == 0 {
                continue;
            }
            let n = room.min(64 << 10).min(s.body.len() - s.sent);
            v.piece_data(s.id, s.body[s.sent..s.sent + n].to_vec())
                .unwrap();
            s.sent += n;
            moved = true;
            break;
        }
        if !moved {
            if let Some(job) = jobs.pop_front() {
                v.hashed(job.run()).unwrap();
                continue;
            }
            return (head, body, "stalled".to_owned());
        }
    }
}

/// One request under the allocator's cap: its memory, at most its budget
/// and the allowance past what the process held before it. Which case runs
/// is written straight to stderr, so a breach's abort names it.
fn bounded(
    case: &str,
    root: &[u8],
    world: &World,
    budget: usize,
    slow_pool: bool,
) -> (Option<u16>, usize, String) {
    use std::io::Write;
    let p = plan(root);
    let _ = writeln!(std::io::stderr(), "dense case: {case}, budget {budget}");
    PEAK.store(0, Ordering::Relaxed);
    let before = ALLOC.allocated();
    ALLOC.set_limit(before + budget + SLACK).unwrap();
    let got = {
        let mut v = Verifier::new(
            1,
            &p,
            Method::Get,
            None,
            false,
            Options {
                budget,
                ..Options::default()
            },
        )
        .unwrap();
        drive(&mut v, world, slow_pool)
    };
    ALLOC.set_limit(usize::MAX).unwrap();
    got
}

/// The entity CAR's path for a root.
fn car_path(root: &[u8]) -> String {
    format!("/ipfs/{}?format=car&dag-scope=entity", text(root))
}

/// A directory of `n` entries, each named `&%` and its number, linking the
/// empty identity CID: its root and the gateway's CAR.
fn directory(n: usize) -> (Vec<u8>, World) {
    let empty = identity(b"");
    let links: Vec<_> = (0..n)
        .map(|i| (empty.clone(), format!("&%{i:05}"), 0))
        .collect();
    let mut data = Vec::new();
    field_varint(1, 1, &mut data);
    let block = pb_node(&links, &data);
    assert!(block.len() < 2 << 20);
    let root = sha256_cid(0x70, &block);
    let mut cars = HashMap::new();
    cars.insert(car_path(&root), Arc::new(car(&[(root.clone(), block)])));
    (root, cars)
}

/// A HAMT of 256 shards under its root, each of 256 entries: 65,536 names.
fn hamt() -> (Vec<u8>, World) {
    let shard_data = || {
        let mut d = Vec::new();
        field_varint(1, 5, &mut d);
        field(2, &[0xff; 32], &mut d);
        field_varint(5, 0x22, &mut d);
        field_varint(6, 256, &mut d);
        d
    };
    let empty = identity(b"");
    let mut shards = Vec::new();
    for s in 0..256usize {
        let links: Vec<_> = (0..256usize)
            .map(|i| (empty.clone(), format!("{i:02X}&%{s:03}{i:03}"), 0))
            .collect();
        let block = pb_node(&links, &shard_data());
        shards.push((sha256_cid(0x70, &block), block));
    }
    let links: Vec<_> = shards
        .iter()
        .enumerate()
        .map(|(s, (cid, _))| (cid.clone(), format!("{s:02X}"), 0))
        .collect();
    let block = pb_node(&links, &shard_data());
    let root = sha256_cid(0x70, &block);
    let mut all = vec![(root.clone(), block)];
    all.extend(shards);
    let mut cars = HashMap::new();
    cars.insert(car_path(&root), Arc::new(car(&all)));
    (root, cars)
}

/// A file node over `n` one-byte identity leaves.
fn wide_file(n: usize) -> (Vec<u8>, World) {
    let links: Vec<_> = (0..n)
        .map(|i| (identity(&[(i % 251) as u8]), String::new(), 1))
        .collect();
    let mut data = Vec::new();
    field_varint(1, 2, &mut data);
    field_varint(3, n as u64, &mut data);
    for _ in 0..n {
        field_varint(4, 1, &mut data);
    }
    let block = pb_node(&links, &data);
    assert!(block.len() < 2 << 20);
    let root = sha256_cid(0x70, &block);
    let mut cars = HashMap::new();
    cars.insert(car_path(&root), Arc::new(car(&[(root.clone(), block)])));
    (root, cars)
}

/// A small file's CAR that, after its root, sends 400,000 sections of the
/// empty identity block, five bytes each on the wire: each hashes right
/// but isn't a leaf the file needs, and each is hashed before that is
/// found, so the sections waiting are bounded with their jobs' own
/// structures counted, not only their bytes. The leaves then come raw.
fn flood() -> (Vec<u8>, World) {
    let a = vec![b'a'; 100];
    let b = vec![b'b'; 100];
    let (la, lb) = (sha256_cid(0x55, &a), sha256_cid(0x55, &b));
    let mut data = Vec::new();
    field_varint(1, 2, &mut data);
    field_varint(3, 200, &mut data);
    field_varint(4, 100, &mut data);
    field_varint(4, 100, &mut data);
    let block = pb_node(
        &[
            (la.clone(), String::new(), 100),
            (lb.clone(), String::new(), 100),
        ],
        &data,
    );
    let root = sha256_cid(0x70, &block);
    let mut sections = vec![(root.clone(), block)];
    for _ in 0..400_000 {
        sections.push((identity(b""), Vec::new()));
    }
    let mut world = HashMap::new();
    world.insert(car_path(&root), Arc::new(car(&sections)));
    world.insert(format!("/ipfs/{}?format=raw", text(&la)), Arc::new(a));
    world.insert(format!("/ipfs/{}?format=raw", text(&lb)), Arc::new(b));
    (root, world)
}

/// Every case in one test, so no other test's allocations meet the cap.
#[test]
fn dense_structure_stays_within_the_budget() {
    // A directory of 65,536 entries whose names escape and encode longer:
    // its entries fit, its page (about 10 MB) doesn't.
    let (root, world) = directory(65_536);
    let got = bounded(
        "directory, 65,536 entries",
        &root,
        &world,
        REQUEST_BUDGET,
        false,
    );
    assert_eq!(got.2, UNVERIFIABLE, "{got:?}");
    // Without room for them, the entries alone are refused: room for the
    // CAR and the block, not for the entries' 3 MiB.
    let got = bounded("directory, 65,536 entries", &root, &world, 15 << 18, false);
    assert_eq!(got.2, UNVERIFIABLE, "{got:?}");
    // A directory whose page fits is listed.
    let (root, world) = directory(5_000);
    let got = bounded(
        "directory, 5,000 entries",
        &root,
        &world,
        REQUEST_BUDGET,
        false,
    );
    assert_eq!((got.0, got.2.as_str()), (Some(200), "end"), "{got:?}");
    assert!(got.1 > 500_000, "{got:?}");
    // A HAMT of 65,536 entries in 257 shards.
    let (root, world) = hamt();
    let got = bounded("HAMT, 65,536 entries", &root, &world, REQUEST_BUDGET, false);
    assert_eq!(got.2, UNVERIFIABLE, "{got:?}");
    // Room for the CAR and the shards, not for the entries.
    let got = bounded("HAMT, 65,536 entries", &root, &world, 4 << 20, false);
    assert_eq!(got.2, UNVERIFIABLE, "{got:?}");
    // A file node of 65,536 children: its worklist doesn't fit 4 MiB, and
    // fits 8 MiB.
    let (root, world) = wide_file(65_536);
    let got = bounded("file, 65,536 children", &root, &world, 4 << 20, false);
    assert_eq!(got.2, UNVERIFIABLE, "{got:?}");
    let got = bounded(
        "file, 65,536 children",
        &root,
        &world,
        REQUEST_BUDGET,
        false,
    );
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), 65_536, "end"),
        "{got:?}"
    );
    // A CAR flooding tiny sections, hashed slowly: answered, from raw
    // blocks, with the sections waiting near their 2 MiB, since a frame is
    // pushed only as far as the sections it can complete may wait.
    let (root, world) = flood();
    let got = bounded(
        "CAR of 400,000 empty sections",
        &root,
        &world,
        REQUEST_BUDGET,
        true,
    );
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), 200, "end"),
        "{got:?}"
    );
    let peak = PEAK.load(Ordering::Relaxed);
    assert!(peak < 5 << 20, "{peak}");
}
