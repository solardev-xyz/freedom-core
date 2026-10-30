//! The verifier's memory, measured by the allocator (design 0009, Bounds:
//! a request's memory is reserved before it is allocated). Requests whose
//! decoded structure would far exceed their budget (a directory's entries,
//! a HAMT's shards and entries, a file node's children, a listing's page,
//! a Swarm lookup's parsed manifest nodes) end `unverifiable` without
//! allocating past it, and those that fit are answered.
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
const SWARM_UNVERIFIABLE: &str =
    "error 502 This content can't be verified with the external Swarm node";

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
                Output::Remember { .. } => {}
                Output::Floor { .. } => v.floor(fc_dweb::store::FloorCheck::Accepted).unwrap(),
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
    capped(case, &plan(root), budget, |v| drive(v, world, slow_pool))
}

/// `drive` on a request for `p` under the allocator's cap.
fn capped<R>(case: &str, p: &Verify, budget: usize, drive: impl FnOnce(&mut Verifier) -> R) -> R {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "dense case: {case}, budget {budget}");
    PEAK.store(0, Ordering::Relaxed);
    let before = ALLOC.allocated();
    ALLOC.set_limit(before + budget + SLACK).unwrap();
    let got = {
        let mut v = Verifier::new(
            1,
            p,
            Method::Get,
            None,
            false,
            Options {
                budget,
                ..Options::default()
            },
        )
        .unwrap();
        drive(&mut v)
    };
    ALLOC.set_limit(usize::MAX).unwrap();
    got
}

// ---------------------------------------------------------------------------
// Swarm manifests.

/// A mantaray v0.2 node as Bee writes it, unobfuscated: its entry, then its
/// forks of (prefix, child, metadata JSON).
fn mantaray(entry: &[u8; 32], forks: &[(Vec<u8>, [u8; 32], Option<String>)]) -> Vec<u8> {
    use sha3::Digest as _;
    let mut p = vec![0u8; 32];
    p.extend_from_slice(&sha3::Keccak256::digest(b"mantaray:0.2")[..31]);
    p.push(32);
    p.extend_from_slice(entry);
    let mut bitmap = [0u8; 32];
    for (prefix, _, _) in forks {
        bitmap[usize::from(prefix[0] / 8)] |= 1 << (prefix[0] % 8);
    }
    p.extend_from_slice(&bitmap);
    let mut sorted = forks.to_vec();
    sorted.sort_by_key(|f| f.0[0]);
    for (prefix, child, meta) in sorted {
        p.push(if meta.is_some() { 2 | 16 } else { 2 });
        p.push(prefix.len() as u8);
        p.extend_from_slice(&prefix);
        p.resize(p.len() + 30 - prefix.len(), 0);
        p.extend_from_slice(&child);
        if let Some(m) = meta {
            let mut padded = m.into_bytes();
            while (padded.len() + 2) % 32 != 0 {
                padded.push(b'\n');
            }
            p.extend_from_slice(&(padded.len() as u16).to_be_bytes());
            p.extend_from_slice(&padded);
        }
    }
    p
}

/// A Swarm file's chunk tree, each chunk added to `chunks` under its
/// `/chunks` path: its root's address.
fn swarm_file(data: &[u8], chunks: &mut World) -> [u8; 32] {
    let mut put = |span: u64, payload: &[u8]| {
        let address = fc_swarm::chunk_address(span, payload).unwrap();
        let mut wire = span.to_le_bytes().to_vec();
        wire.extend_from_slice(payload);
        chunks.insert(format!("/chunks/{}", hex::encode(address)), Arc::new(wire));
        (address, span)
    };
    let mut level: Vec<([u8; 32], u64)> = data
        .chunks(4096)
        .map(|leaf| put(leaf.len() as u64, leaf))
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(128)
            .map(|group| {
                let span = group.iter().map(|(_, s)| s).sum();
                let payload: Vec<u8> = group.iter().flat_map(|(a, _)| a.to_vec()).collect();
                put(span, &payload)
            })
            .collect();
    }
    level[0].0
}

/// A manifest whose two nodes are mostly metadata the lookup keeps: seven
/// forks each with a 60,000-byte `Filename`, about 420 KB a node. The root's
/// fork `a/` leads to the other node, which has no fork `q`, so `/a/q`
/// loads it twice and is a 404. Its root, Ant's chunks, what the parsed
/// root holds, and the other node's length.
fn big_manifest() -> (String, World, usize, usize) {
    let meta = |c: u8| {
        let name = char::from(c).to_string().repeat(60_000);
        Some(format!(r#"{{"Filename":"{name}"}}"#))
    };
    let mut chunks = HashMap::new();
    let forks: Vec<_> = (b'b'..=b'h')
        .map(|c| (vec![c], [0x11; 32], meta(c)))
        .collect();
    let child = mantaray(&[0; 32], &forks);
    let child_address = swarm_file(&child, &mut chunks);
    let mut root_forks = forks[..6].to_vec();
    root_forks.push((b"a/".to_vec(), child_address, meta(b'a')));
    let root = mantaray(&[0; 32], &root_forks);
    let root_cost = fc_swarm::manifest::parse_node(&root).unwrap().cost();
    let address = swarm_file(&root, &mut chunks);
    (hex::encode(address), chunks, root_cost, child.len())
}

fn swarm_plan(root: &str, path: &str) -> Verify {
    let backend = Backend::ant(fc_dweb::Ant::External, true);
    Verify {
        node: Node::Ant,
        root: Root::Swarm(root.to_owned()),
        path: path.to_owned(),
        query: String::new(),
        headers: vec![],
        retry: retry(backend),
        timers: timers(backend),
        response: vec![ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
        trust: Trust {
            name: None,
            content: ContentTrust::Verified,
        },
    }
}

/// A Swarm request through main, the hashing pool and a page that reads at
/// once, against an Ant that answers `/chunks` from `chunks`: as `drive`.
fn swarm_drive(v: &mut Verifier, chunks: &World) -> (Option<u16>, usize, String) {
    let mut jobs = VecDeque::new();
    let mut asked = VecDeque::new();
    let (mut head, mut body) = (None, 0);
    loop {
        PEAK.fetch_max(v.reserved(), Ordering::Relaxed);
        while let Some(o) = v.poll() {
            match o {
                Output::Piece(r) => asked.push_back(r),
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
                Output::CancelPiece(_)
                | Output::Credit { .. }
                | Output::Remember { .. }
                | Output::Floor { .. } => {}
            }
        }
        if let Some(job) = jobs.pop_front() {
            v.hashed(job.run()).unwrap();
            continue;
        }
        let Some(r) = asked.pop_front() else {
            return (head, body, "stalled".to_owned());
        };
        assert!(!r.stream, "{}", r.path);
        match chunks.get(&r.path) {
            Some(wire) => v.piece_whole(r.id, 200, vec![], wire.to_vec()).unwrap(),
            None => v
                .piece_whole(
                    r.id,
                    404,
                    vec![],
                    br#"{"code":404,"message":"Not Found"}"#.to_vec(),
                )
                .unwrap(),
        }
    }
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
    // A Swarm lookup holds its root parsed beside the next node's join, and
    // both count: the reservation's peak covers them.
    let (root, chunks, root_cost, child_len) = big_manifest();
    let p = swarm_plan(&root, "/a/q");
    let got = capped("manifest, nodes of 420 KB", &p, REQUEST_BUDGET, |v| {
        swarm_drive(v, &chunks)
    });
    assert_eq!((got.0, got.2.as_str()), (Some(404), "end"), "{got:?}");
    let peak = PEAK.load(Ordering::Relaxed);
    assert!(
        peak >= root_cost + child_len,
        "{peak} < {root_cost} + {child_len}"
    );
    // A Swarm request's 2 MiB fits them.
    let got = capped("manifest, nodes of 420 KB", &p, 2 << 20, |v| {
        swarm_drive(v, &chunks)
    });
    assert_eq!((got.0, got.2.as_str()), (Some(404), "end"), "{got:?}");
    // 1 MiB has room for the root and one node's join, not for the root
    // parsed beside the join and its parse: unverifiable, without
    // allocating past it.
    let got = capped("manifest, nodes of 420 KB", &p, 1 << 20, |v| {
        swarm_drive(v, &chunks)
    });
    assert_eq!(got.2, SWARM_UNVERIFIABLE, "{got:?}");
}
