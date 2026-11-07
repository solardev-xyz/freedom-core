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
//!
//! What the tests read from the allocator, what it holds and the most it
//! held, is the count of one thread: the test's. Each test runs holding
//! [`one_at_a_time`], which marks its thread counted, and the allocator
//! reports every allocation and release to [`Counted`], which counts only
//! a counted thread's. The request, its machine and the driver, which runs
//! the hashing jobs too, all run on that thread, so the count is still all
//! the request allocates; what the test harness's own threads allocate
//! beside it (the next test's thread started, a finished test's result
//! taken) isn't in it.
//!
//! The cap stays the process's. It refuses an allocation before it is
//! made, and refusing by thread would take an allocator of this file's
//! own, which the workspace's `forbid(unsafe_code)` rules out. Another
//! thread's allocations only bring its abort sooner; what one frees during
//! a request (the harness's few bytes) gives the request that much more
//! room beside its 256 KiB allowance. The bounds the tests assert are on
//! the thread's count.
//!
//! For the Swarm lookup, the allocator's own high-water mark is read too,
//! from the request's start: what it allocated at its peak, beside what the
//! machine reserved at its peak by its own count ([`Verifier::peak`]), must
//! be within a fixed allowance for the machine and the driver, measured on
//! a small manifest. Every release must match a hold
//! ([`Verifier::over_released`]).
//!
//! With the `memory-probe` feature, every request reads the allocator at
//! every release of its walk's memory, inside each input: what is live
//! then must be within the machine's reservation and the same allowance,
//! so a buffer whose charge goes before it does is caught where it
//! happens, not only between inputs. Each input also ends with the walk's
//! holding equal to what its live values are charged
//! ([`Verifier::over_released`]).
//!
//! `allocations_stay_within_the_grant` holds requests to their grant
//! (0009, What a grant covers): between inputs, within each input (the
//! allocator's peak in it beside the machine's) and at the request's peak,
//! what is allocated passes the reservation by no more than the scheme's
//! allowance, for streams in 1-byte and 64 KiB frames, raw blocks of known
//! and unknown length, and small body slices, main taking the outputs after
//! every input or only once nothing moves without them
//! ([`Poll::WhenStuck`]).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::alloc::System;
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cap::Cap;
use fc_dweb::verifier::{
    IPFS_ALLOWANCE, IPFS_BUDGET, IPFS_GRANT, Job, MAX_FRAME, MAX_PATH, Method, Options, Output,
    PieceId, REQUEST_BUDGET, STREAM_WINDOW, SWARM_ALLOWANCE, SWARM_BUDGET, SWARM_GRANT, Verifier,
};
use fc_dweb::{
    Backend, ContentTrust, Ipfs, Node, Refusal, ResponseOp, Root, Trust, Verify, retry, timers,
};
use sha2::Digest;
use tracking_allocator::{AllocationGroupId, AllocationRegistry, AllocationTracker, Allocator};

/// The cap around an allocator that reports every allocation and release
/// to [`Counted`].
#[global_allocator]
static ALLOC: Cap<Allocator<System>> = Cap::new(Allocator::system(), usize::MAX);

thread_local! {
    /// Whether the allocator counts this thread: while it runs a test here
    /// ([`one_at_a_time`]). Const, with nothing to drop, so the allocator
    /// reads it without allocating, and still can while the thread's other
    /// locals are torn down.
    static COUNTED: Cell<bool> = const { Cell::new(false) };
}

/// What the counted thread holds, and the most it held since
/// [`Counted::reset_peak_usage`]. One thread is counted at a time.
static HELD: AtomicUsize = AtomicUsize::new(0);
static MOST: AtomicUsize = AtomicUsize::new(0);

/// The counted thread's allocations, with a high-water mark that resets,
/// for each request's real peak.
#[derive(Clone, Copy)]
struct Counted;

impl Counted {
    /// What the counted thread holds.
    fn current_usage(self) -> usize {
        HELD.load(Ordering::Relaxed)
    }

    /// The most the counted thread held since the last reset.
    fn peak_usage(self) -> usize {
        MOST.load(Ordering::Relaxed)
    }

    /// Starts the high-water mark again from what the thread holds now.
    fn reset_peak_usage(self) {
        MOST.store(HELD.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

/// Whether the allocator counts the thread it runs on.
fn counted() -> bool {
    COUNTED.try_with(Cell::get).unwrap_or(false)
}

/// Called by the allocator on every thread, after each allocation and
/// release: it counts the counted thread's, and allocates nothing.
impl AllocationTracker for Counted {
    fn allocated(&self, _addr: usize, size: usize, _wrapped: usize, _group: AllocationGroupId) {
        if counted() {
            let held = HELD.fetch_add(size, Ordering::Relaxed) + size;
            MOST.fetch_max(held, Ordering::Relaxed);
        }
    }

    fn deallocated(
        &self,
        _addr: usize,
        size: usize,
        _wrapped: usize,
        _source: AllocationGroupId,
        _current: AllocationGroupId,
    ) {
        if counted() {
            // A release of what the thread held before it was counted
            // (nothing a test here releases) can't take the count below
            // nothing.
            HELD.update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                held.saturating_sub(size)
            });
        }
    }
}

/// The most the last request reserved at any step.
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// What the allocator held when the last request started.
static BASE: AtomicUsize = AtomicUsize::new(0);
/// The most the allocator held past the machine's reservation at any
/// release of the walk's memory, in the last request, and the reservation
/// then.
static AT_RELEASE: AtomicUsize = AtomicUsize::new(0);
static AT_RELEASE_RESERVED: AtomicUsize = AtomicUsize::new(0);
/// The most the allocator held past the machine's reservation between two
/// inputs, the request's outputs taken, in the last request.
static BETWEEN: AtomicUsize = AtomicUsize::new(0);
/// The tests here one at a time: the cap is the process's, and one thread
/// at a time is counted.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A test's hold on the binary: no other test here runs, and the allocator
/// counts the test's thread until the hold is dropped.
struct OneAtATime {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Drop for OneAtATime {
    /// The thread stops being counted before the next test's starts.
    fn drop(&mut self) {
        COUNTED.set(false);
    }
}

/// Waits for the other tests here, then counts this thread. A test takes
/// it first, so its other locals are released while it is still counted.
fn one_at_a_time() -> OneAtATime {
    static TRACKER: std::sync::Once = std::sync::Once::new();
    let lock = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    TRACKER.call_once(|| {
        AllocationRegistry::set_global_tracker(Counted).unwrap();
        AllocationRegistry::enable_tracking();
    });
    // The allocator's own state for this thread is set up at its first
    // report here, which may allocate (a destructor's registration, on some
    // platforms): before the thread is counted.
    drop(std::hint::black_box(Box::new(0u8)));
    COUNTED.set(true);
    OneAtATime { _lock: lock }
}

/// The most credits main took with no input between them, in the last
/// request: what waited among the outputs at once.
static CREDITS_WAITING: AtomicUsize = AtomicUsize::new(0);

/// When main takes the machine's outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Poll {
    /// All of them after every input.
    Each,
    /// Only once it can't go on without them: it sends all it has room
    /// for (a stream's whole window, in its frames), answers the pieces
    /// and runs the jobs it has, and polls only then. Nothing in the
    /// machine's contract asks main to poll between inputs.
    WhenStuck,
}

/// The hashing pool's next job. Its queue gives back its slots as it
/// drains: room it keeps for jobs that came back is the pool's, not the
/// request's, whose jobs' structures count while they are out.
fn next_job(jobs: &mut VecDeque<Job>) -> Option<Job> {
    let job = jobs.pop_front();
    if jobs.capacity() > 64 && jobs.len() * 4 < jobs.capacity() {
        jobs.shrink_to(jobs.len() * 2);
    }
    job
}

/// The allocator's and the machine's peaks before the last input, which
/// [`input`] starts again for each.
static ALLOC_BEFORE: AtomicUsize = AtomicUsize::new(0);
static LEDGER_BEFORE: AtomicUsize = AtomicUsize::new(0);
/// The most the allocator reached within one input past the most the
/// machine reserved within it, in the last request.
static IN_INPUT: AtomicUsize = AtomicUsize::new(0);

/// One input, with the memory probe: what the allocator reached within it
/// is held to what the machine reserved at most within it, so a buffer
/// moved or cut without room for the old one beside it is caught, though
/// the request's own peak lies elsewhere.
fn input<R>(v: &mut Verifier, f: impl FnOnce(&mut Verifier) -> R) -> R {
    #[cfg(feature = "memory-probe")]
    {
        ALLOC_BEFORE.fetch_max(Counted.peak_usage(), Ordering::Relaxed);
        LEDGER_BEFORE.fetch_max(v.peak(), Ordering::Relaxed);
        Counted.reset_peak_usage();
        v.reset_peak();
    }
    let r = f(v);
    #[cfg(feature = "memory-probe")]
    {
        let reached = Counted
            .peak_usage()
            .saturating_sub(BASE.load(Ordering::Relaxed));
        IN_INPUT.fetch_max(reached.saturating_sub(v.peak()), Ordering::Relaxed);
    }
    r
}

/// Between inputs, the outputs taken: what is live past the reservation.
fn between(v: &Verifier) {
    let now = Counted
        .current_usage()
        .saturating_sub(BASE.load(Ordering::Relaxed));
    BETWEEN.fetch_max(now.saturating_sub(v.reserved()), Ordering::Relaxed);
}

/// At a release of the walk's memory: what is live past the reservation.
#[cfg(feature = "memory-probe")]
fn at_release(reserved: usize) {
    let now = Counted
        .current_usage()
        .saturating_sub(BASE.load(Ordering::Relaxed));
    let past = now.saturating_sub(reserved);
    if past > AT_RELEASE.fetch_max(past, Ordering::Relaxed) {
        AT_RELEASE_RESERVED.store(reserved, Ordering::Relaxed);
    }
}

/// What the driver and the machine's fixed structures may take beside the
/// request's budget.
const SLACK: usize = 256 << 10;
/// What a walk's machine and its driver allocate beside what the machine
/// reserves: its own structures, the outputs it queues and the driver's
/// queues. Measured on a manifest of small nodes, and held to for the large
/// ones and for every IPFS request.
const MACHINE: usize = 48 << 10;
const CAR_TYPE: &str = "application/vnd.ipld.car; version=1; order=dfs; dups=y";
const RAW_TYPE: &str = "application/vnd.ipld.raw";
/// A request refused for its memory, either scheme.
const MEMORY_REFUSED: &str =
    "error 502 This content needs more memory to verify than one request may use";

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
    drive_framed(v, world, slow_pool, MAX_FRAME)
}

/// [`drive`], main sending each stream in frames of at most `frame` bytes.
fn drive_framed(
    v: &mut Verifier,
    world: &World,
    slow_pool: bool,
    frame: usize,
) -> (Option<u16>, usize, String) {
    drive_paged(v, world, slow_pool, frame, true, Poll::Each)
}

/// [`drive_framed`]; without `reads`, a page that never reads, so the
/// request stalls once its body's window is out; main taking the outputs
/// as `poll` says.
fn drive_paged(
    v: &mut Verifier,
    world: &World,
    slow_pool: bool,
    frame: usize,
    reads: bool,
    poll: Poll,
) -> (Option<u16>, usize, String) {
    let mut jobs = VecDeque::new();
    let mut asked = VecDeque::new();
    let mut streams: Vec<Stream> = Vec::new();
    let (mut head, mut body) = (None, 0);
    // Main takes the outputs now; it took them since its last input.
    let mut take = true;
    loop {
        PEAK.fetch_max(v.reserved(), Ordering::Relaxed);
        let taken = take || poll == Poll::Each;
        take = false;
        let mut credits = 0;
        while taken && let Some(o) = v.poll() {
            match o {
                // Main sends the request on and keeps only the piece's
                // number: the driver finds its answer now, and keeps no
                // copy of its path.
                Output::Piece(r) => {
                    let answer = world
                        .get(&r.path)
                        .unwrap_or_else(|| panic!("{}", r.path))
                        .clone();
                    let kind = if r.path.ends_with("format=ipns-record") {
                        None
                    } else if r.path.ends_with("format=raw") {
                        Some(RAW_TYPE)
                    } else {
                        Some(CAR_TYPE)
                    };
                    asked.push_back((r.id, kind, answer));
                }
                Output::CancelPiece(id) => {
                    if let Some(s) = streams.iter_mut().find(|s| s.id == id) {
                        s.cancelled = true;
                    }
                }
                Output::Credit { piece, bytes } => {
                    credits += 1;
                    CREDITS_WAITING.fetch_max(credits, Ordering::Relaxed);
                    if let Some(s) = streams.iter_mut().find(|s| s.id == piece) {
                        s.credited += bytes;
                    }
                }
                Output::Hash(job) => jobs.push_back(job),
                Output::Remember { .. } => {}
                Output::Floor { .. } => {
                    credits = 0;
                    input(v, |v| v.floor(fc_dweb::store::FloorCheck::Accepted)).unwrap()
                }
                // A head with no body after it (a HEAD's) ends the request.
                Output::Head(h) if !h.body => return (Some(h.status), body, "head".to_owned()),
                Output::Head(h) => head = Some(h.status),
                Output::Body(b) => {
                    body += b.len();
                    let n = b.len();
                    drop(b);
                    if reads {
                        credits = 0;
                        input(v, |v| v.body_credit(n)).unwrap();
                    }
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
        between(v);
        // A job runs as the pool runs it, then its result is the machine's
        // input: the pool's own work (an IPNS record's signed data, copied
        // for its check) is the pool's, not the request's.
        if !slow_pool && let Some(job) = next_job(&mut jobs) {
            let result = job.run();
            input(v, |v| v.hashed(result)).unwrap();
            continue;
        }
        if let Some((id, kind, answer)) = asked.pop_front() {
            let Some(kind) = kind else {
                input(v, |v| v.piece_whole(id, 200, vec![], answer.to_vec())).unwrap();
                continue;
            };
            input(v, |v| {
                v.piece_head(id, 200, vec![("content-type".to_owned(), kind.to_owned())])
            })
            .unwrap();
            streams.push(Stream {
                id,
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
                input(v, |v| v.piece_end(s.id)).unwrap();
                s.done = true;
                moved = true;
                break;
            }
            let room = STREAM_WINDOW - (s.sent - s.credited);
            if room == 0 {
                continue;
            }
            let n = room.min(frame).min(s.body.len() - s.sent);
            input(v, |v| {
                v.piece_data(s.id, s.body[s.sent..s.sent + n].to_vec())
            })
            .unwrap();
            s.sent += n;
            moved = true;
            break;
        }
        // An ended stream is main's no longer: the driver keeps only those
        // open, as main does, so its own memory doesn't grow with a walk's
        // many blocks.
        streams.retain(|s| !s.done);
        if !moved {
            if let Some(job) = next_job(&mut jobs) {
                let result = job.run();
                input(v, |v| v.hashed(result)).unwrap();
                continue;
            }
            if !taken {
                take = true;
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
    capped(case, &plan(root), budget, |v| drive(v, world, slow_pool)).0
}

/// What a request's memory came to: the allocator's peak from its start,
/// and the machine's own reservation at its peak.
#[derive(Debug, Clone, Copy)]
struct Measured {
    allocated: usize,
    reserved: usize,
}

/// `drive` on a request for `p` under the allocator's cap: what it gave,
/// and what its memory came to.
fn capped<R>(
    case: &str,
    p: &Verify,
    budget: usize,
    drive: impl FnOnce(&mut Verifier) -> R,
) -> (R, Measured) {
    capped_with(
        case,
        p,
        Options {
            budget,
            ..Options::default()
        },
        drive,
    )
}

/// [`capped`] with the request's options.
fn capped_with<R>(
    case: &str,
    p: &Verify,
    options: Options,
    drive: impl FnOnce(&mut Verifier) -> R,
) -> (R, Measured) {
    capped_as(case, p, Method::Get, options, drive)
}

/// [`capped_with`] for a request of `method`.
fn capped_as<R>(
    case: &str,
    p: &Verify,
    method: Method,
    options: Options,
    drive: impl FnOnce(&mut Verifier) -> R,
) -> (R, Measured) {
    use std::io::Write;
    let budget = options.budget;
    let _ = writeln!(std::io::stderr(), "dense case: {case}, budget {budget}");
    PEAK.store(0, Ordering::Relaxed);
    BETWEEN.store(0, Ordering::Relaxed);
    CREDITS_WAITING.store(0, Ordering::Relaxed);
    IN_INPUT.store(0, Ordering::Relaxed);
    ALLOC_BEFORE.store(0, Ordering::Relaxed);
    LEDGER_BEFORE.store(0, Ordering::Relaxed);
    let before = ALLOC.allocated();
    ALLOC.set_limit(before + budget + SLACK).unwrap();
    Counted.reset_peak_usage();
    let base = Counted.current_usage();
    BASE.store(base, Ordering::Relaxed);
    AT_RELEASE.store(0, Ordering::Relaxed);
    AT_RELEASE_RESERVED.store(0, Ordering::Relaxed);
    #[cfg(feature = "memory-probe")]
    fc_dweb::verifier::probe::at_release(Some(at_release));
    let (got, reserved) = {
        let mut v = Verifier::new(1, p, method, None, false, options).unwrap();
        let got = drive(&mut v);
        assert_eq!(v.over_released(), 0, "{case}: released without a hold");
        (got, v.peak().max(LEDGER_BEFORE.load(Ordering::Relaxed)))
    };
    #[cfg(feature = "memory-probe")]
    fc_dweb::verifier::probe::at_release(None);
    let allocated = Counted
        .peak_usage()
        .max(ALLOC_BEFORE.load(Ordering::Relaxed))
        .saturating_sub(base);
    ALLOC.set_limit(usize::MAX).unwrap();
    // Within each input too, at every release: nothing the walk released
    // was still live past the allowance.
    let past = AT_RELEASE.load(Ordering::Relaxed);
    let _ = writeln!(
        std::io::stderr(),
        "  {case}: at a release, {past} allocated past the reservation {}",
        AT_RELEASE_RESERVED.load(Ordering::Relaxed)
    );
    assert!(
        past <= MACHINE,
        "{case}: at a release, {past} allocated past the reservation {}",
        AT_RELEASE_RESERVED.load(Ordering::Relaxed)
    );
    (
        got,
        Measured {
            allocated,
            reserved,
        },
    )
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
    manifest_of(7, 60_000)
}

/// [`big_manifest`] with `forks` forks a node, each with a `Filename` of
/// `len` bytes.
fn manifest_of(forks: u8, len: usize) -> (String, World, usize, usize) {
    let meta = |c: u8| {
        let name = char::from(c).to_string().repeat(len);
        Some(format!(r#"{{"Filename":"{name}"}}"#))
    };
    let mut chunks = HashMap::new();
    let forks: Vec<_> = (b'b'..b'b' + forks)
        .map(|c| (vec![c], [0x11; 32], meta(c)))
        .collect();
    let child = mantaray(&[0; 32], &forks);
    let child_address = swarm_file(&child, &mut chunks);
    let mut root_forks = forks[..forks.len() - 1].to_vec();
    root_forks.push((b"a/".to_vec(), child_address, meta(b'a')));
    let root = mantaray(&[0; 32], &root_forks);
    let root_cost = fc_swarm::manifest::parse_node(&root).unwrap().cost();
    let address = swarm_file(&root, &mut chunks);
    (hex::encode(address), chunks, root_cost, child.len())
}

/// A manifest whose entry `a/b` has the most metadata a fork carries: a
/// `Filename` of 65,000 bytes, beside six forks of 60,000 each, so its
/// node is about 425 KB. Its root, Ant's chunks, and the file's root
/// chunk's path.
fn found_manifest() -> (String, World, String) {
    let mut chunks = HashMap::new();
    let data = b"twelve bytes".to_vec();
    let file = swarm_file(&data, &mut chunks);
    let value = swarm_file(&mantaray(&file, &[]), &mut chunks);
    let meta = |c: u8, n: usize| {
        let name = char::from(c).to_string().repeat(n);
        Some(format!(
            r#"{{"Content-Type":"text/plain","Filename":"{name}"}}"#
        ))
    };
    let mut forks = vec![(b"b".to_vec(), value, meta(b'b', 65_000))];
    forks.extend((b'c'..=b'h').map(|c| (vec![c], [0x11; 32], meta(c, 60_000))));
    let child = swarm_file(&mantaray(&[0; 32], &forks), &mut chunks);
    let root = mantaray(&[0; 32], &[(b"a/".to_vec(), child, None)]);
    let address = swarm_file(&root, &mut chunks);
    (
        hex::encode(address),
        chunks,
        format!("/chunks/{}", hex::encode(file)),
    )
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
    swarm_drive_watching(v, chunks, Poll::Each, false, |_, _| {})
}

/// [`swarm_drive`], main taking the outputs as `poll` says, with
/// `slow_pool` running jobs only once no piece can move, and calling `asked`
/// with each piece as it is asked for.
fn swarm_drive_watching(
    v: &mut Verifier,
    chunks: &World,
    poll: Poll,
    slow_pool: bool,
    mut asked_for: impl FnMut(&fc_dweb::verifier::PieceRequest, &Verifier),
) -> (Option<u16>, usize, String) {
    let mut jobs = VecDeque::new();
    let mut asked = VecDeque::new();
    let (mut head, mut body) = (None, 0);
    let mut take = true;
    loop {
        PEAK.fetch_max(v.reserved(), Ordering::Relaxed);
        assert_eq!(v.over_released(), 0, "released without a hold");
        let taken = take || poll == Poll::Each;
        take = false;
        while taken && let Some(o) = v.poll() {
            match o {
                Output::Piece(r) => {
                    asked_for(&r, v);
                    asked.push_back(r);
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
                Output::CancelPiece(_)
                | Output::Credit { .. }
                | Output::Remember { .. }
                | Output::Floor { .. } => {}
            }
        }
        // Between inputs, its outputs taken, what is allocated is what the
        // machine holds, and the jobs and pieces it handed out.
        let now = Counted
            .current_usage()
            .saturating_sub(BASE.load(Ordering::Relaxed));
        if poll == Poll::Each {
            assert!(
                now <= v.reserved() + MACHINE,
                "allocated {now}, reserved {}",
                v.reserved()
            );
        }
        between(v);
        if (!slow_pool || asked.is_empty())
            && let Some(job) = next_job(&mut jobs)
        {
            v.hashed(job.run()).unwrap();
            continue;
        }
        let Some(r) = asked.pop_front() else {
            if !taken {
                take = true;
                continue;
            }
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
    let (root, block) = directory_block(n);
    let mut cars = HashMap::new();
    cars.insert(car_path(&root), Arc::new(car(&[(root.clone(), block)])));
    (root, cars)
}

/// [`directory`]'s root and block.
fn directory_block(n: usize) -> (Vec<u8>, Vec<u8>) {
    let empty = identity(b"");
    let links: Vec<_> = (0..n)
        .map(|i| (empty.clone(), format!("&%{i:05}"), 0))
        .collect();
    let mut data = Vec::new();
    field_varint(1, 1, &mut data);
    let block = pb_node(&links, &data);
    assert!(block.len() < 2 << 20);
    (sha256_cid(0x70, &block), block)
}

/// A directory of `n` entries named `f` and five digits, linking the
/// empty identity CID: its root and block.
fn names_block(n: usize) -> (Vec<u8>, Vec<u8>) {
    names_block_padded(n, 0)
}

/// [`names_block`], each name followed by `pad` `x`s.
fn names_block_padded(n: usize, pad: usize) -> (Vec<u8>, Vec<u8>) {
    let x = "x".repeat(pad);
    let links: Vec<_> = (0..n)
        .map(|i| (identity(b""), format!("f{i:05}{x}"), 0))
        .collect();
    let mut data = Vec::new();
    field_varint(1, 1, &mut data);
    let block = pb_node(&links, &data);
    (sha256_cid(0x70, &block), block)
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
    flood_then(400_000, 0)
}

/// [`flood`] of `n` empty sections, then, past `0`, a raw block of
/// `tail` bytes, which the file doesn't need either.
fn flood_then(n: usize, tail: usize) -> (Vec<u8>, World) {
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
    let mut world = HashMap::new();
    // The root raw too, for a CAR that gives way before its first section
    // is used.
    world.insert(
        format!("/ipfs/{}?format=raw", text(&root)),
        Arc::new(block.clone()),
    );
    let mut sections = vec![(root.clone(), block)];
    for _ in 0..n {
        sections.push((identity(b""), Vec::new()));
    }
    if tail > 0 {
        let big: Vec<u8> = (0..tail).map(|i| (i % 251) as u8).collect();
        sections.push((sha256_cid(0x55, &big), big));
    }
    world.insert(car_path(&root), Arc::new(car(&sections)));
    world.insert(format!("/ipfs/{}?format=raw", text(&la)), Arc::new(a));
    world.insert(format!("/ipfs/{}?format=raw", text(&lb)), Arc::new(b));
    (root, world)
}

/// Every case in one test, so no other test's allocations meet the cap.
/// The IPNS sequence floors fully occupied (0009, Bounds): 1,024 names in
/// the profile's partition and in each of eight private ones, each name an
/// Ed25519 libp2p-key CID as the walk keys it: CIDv1, the libp2p-key codec,
/// the identity multihash and the 36-byte `PublicKey` protobuf, 40 bytes.
/// They arrive in order, which leaves the floors' B-trees least full: the
/// most of the orders measured (uniform keys, in no order, hold about
/// 2.02 MB). What the allocator holds for them past the store and its
/// partitions, and with them.
///
/// The structure is the same every time, and so is every reading of it
/// (2,184,048 bytes on 64-bit Linux): the count is the test thread's (the
/// module doc), so the harness's other threads, which once moved a reading
/// by 9,713 bytes while the count was the process's, aren't in it. The
/// floors are measured until two readings in a row agree all the same.
fn floors_fully_occupied() -> (usize, usize) {
    let mut readings = vec![floors_reading()];
    while readings.len() < 8 {
        let next = floors_reading();
        if readings.last() == Some(&next) {
            return next;
        }
        readings.push(next);
    }
    panic!("no two readings in a row agree: {readings:?}");
}

/// One reading of [`floors_fully_occupied`].
fn floors_reading() -> (usize, usize) {
    use fc_dweb::store::{FLOOR_NAMES, FloorCheck, PRIVATE_PARTITIONS, Store};
    let start = Counted.current_usage();
    let mut store = Store::new();
    let partitions: Vec<Option<String>> = std::iter::once(None)
        .chain((0..PRIVATE_PARTITIONS).map(|i| Some(format!("private-{i}"))))
        .collect();
    let tickets: Vec<_> = partitions
        .iter()
        .map(|p| store.begin(p.as_deref()))
        .collect();
    let base = Counted.current_usage();
    let mut name = [0u8; 40];
    name[..8].copy_from_slice(&[0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
    for (t, ticket) in tickets.iter().enumerate() {
        for i in 0..FLOOR_NAMES {
            name[8] = t as u8;
            name[9..17].copy_from_slice(&(i as u64).to_be_bytes());
            let check = store.floor(ticket, &name, 1, i64::MAX, 0);
            assert_eq!(check, FloorCheck::Accepted);
        }
    }
    for p in &partitions {
        assert_eq!(store.floors(p.as_deref()), FLOOR_NAMES, "{p:?}");
    }
    let now = Counted.current_usage();
    drop((store, tickets, partitions));
    (now.saturating_sub(base), now.saturating_sub(start))
}

#[test]
fn dense_structure_stays_within_the_budget() {
    let _one = one_at_a_time();
    // The IPNS floors, fully occupied, within their 3 MiB reserve beside
    // the structure cache, and the 2.18 MB 0009 states for them.
    let (held, with_setup) = floors_fully_occupied();
    {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "floors: {held} bytes, {with_setup} with the store's setup"
        );
    }
    assert!(with_setup <= 3 << 20, "{with_setup}");
    assert!(
        (2_175_000..2_185_000).contains(&held),
        "{held}: 0009 states 2.18 MB"
    );
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
    assert_eq!(got.2, MEMORY_REFUSED, "{got:?}");
    // Without room for them, the entries alone are refused: room for the
    // CAR and the block, not for the entries' 3 MiB.
    let got = bounded("directory, 65,536 entries", &root, &world, 15 << 18, false);
    assert_eq!(got.2, MEMORY_REFUSED, "{got:?}");
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
    assert_eq!(got.2, MEMORY_REFUSED, "{got:?}");
    // Room for the CAR and the shards, not for the entries.
    let got = bounded("HAMT, 65,536 entries", &root, &world, 4 << 20, false);
    assert_eq!(got.2, MEMORY_REFUSED, "{got:?}");
    // A file node of 65,536 children: its worklist doesn't fit 4 MiB, and
    // fits 8 MiB.
    let (root, world) = wide_file(65_536);
    let got = bounded("file, 65,536 children", &root, &world, 4 << 20, false);
    assert_eq!(got.2, MEMORY_REFUSED, "{got:?}");
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

    // The Swarm lookup. First the fixed allowance: a manifest of small
    // nodes, whose reservation is small, shows what the machine and the
    // driver allocate beside what the machine reserves.
    let (root, chunks, _, _) = manifest_of(2, 10);
    let p = swarm_plan(&root, "/a/q");
    let (got, m) = capped("manifest, small nodes", &p, REQUEST_BUDGET, |v| {
        swarm_drive(v, &chunks)
    });
    assert_eq!((got.0, got.2.as_str()), (Some(404), "end"), "{got:?}");
    let fixed = m.allocated.saturating_sub(m.reserved);
    assert!(fixed <= MACHINE, "{m:?}: the machine's own {fixed}");
    // A lookup holds its root parsed beside the next node's join and its
    // parse, and each counts: what the allocator gave never passes what
    // the machine reserved by more than that allowance.
    let (root, chunks, root_cost, child_len) = big_manifest();
    let p = swarm_plan(&root, "/a/q");
    let (got, m) = capped("manifest, nodes of 420 KB", &p, REQUEST_BUDGET, |v| {
        swarm_drive(v, &chunks)
    });
    assert_eq!((got.0, got.2.as_str()), (Some(404), "end"), "{got:?}");
    assert!(
        m.reserved >= root_cost + 2 * child_len,
        "{m:?}: {root_cost} + 2 x {child_len}"
    );
    assert!(m.allocated <= m.reserved + MACHINE, "{m:?}");
    // A Swarm request's budget fits them.
    let (got, m) = capped("manifest, nodes of 420 KB", &p, SWARM_BUDGET, |v| {
        swarm_drive(v, &chunks)
    });
    assert_eq!((got.0, got.2.as_str()), (Some(404), "end"), "{got:?}");
    assert!(m.allocated <= m.reserved + MACHINE, "{m:?}");
    // 1 MiB has room for the root and one node's join, not for the root
    // parsed beside the join and its parse: unverifiable, without
    // allocating past it.
    let (got, m) = capped("manifest, nodes of 420 KB", &p, 1 << 20, |v| {
        swarm_drive(v, &chunks)
    });
    assert_eq!(got.2, MEMORY_REFUSED, "{got:?}");
    assert!(m.allocated <= m.reserved + MACHINE, "{m:?}");
    // An entry with the most metadata a fork carries: its strings move
    // into the entry, which holds them while the file's root chunk is
    // fetched, and the head copies them within room of its own.
    let (root, chunks, file_root) = found_manifest();
    let p = swarm_plan(&root, "/a/b");
    let mut waited = false;
    let (got, m) = capped("manifest, a 65,000-byte entry", &p, SWARM_BUDGET, |v| {
        swarm_drive_watching(v, &chunks, Poll::Each, false, |piece, v| {
            if piece.path == file_root {
                assert!(v.reserved() >= 65_000, "the entry: {}", v.reserved());
                waited = true;
            }
        })
    });
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), 12, "end"),
        "{got:?}"
    );
    assert!(waited);
    assert!(m.allocated <= m.reserved + MACHINE, "{m:?}");
    // The same entry, its file's root chunk missing: the request ends on
    // the 404, and the entry goes before its charge does.
    let (root, mut chunks, file_root) = found_manifest();
    chunks.remove(&file_root);
    let p = swarm_plan(&root, "/a/b");
    let (got, m) = capped(
        "manifest, a 65,000-byte entry, no file",
        &p,
        SWARM_BUDGET,
        |v| swarm_drive(v, &chunks),
    );
    assert_eq!(got.0, None, "{got:?}");
    assert!(got.2.starts_with("error "), "{got:?}");
    assert!(m.allocated <= m.reserved + MACHINE, "{m:?}");
}

// ---------------------------------------------------------------------------
// What a request allocates past what its budget counts: within its grant's
// allowance, however main frames its streams.

/// A Swarm file of `leaves` 4 KiB leaves streamed through `/bytes`, its
/// tree's second level-1 chunk held back: a range from the last leaf under
/// the first, so once that leaf is in, the stream's bytes wait in its stash
/// for the held chunk. The manifest's root, Ant's chunks, the file, the
/// held chunk's path and the range's start.
fn stashed_swarm_file(leaves: usize) -> (String, World, Vec<u8>, String, usize) {
    let data: Vec<u8> = (0..leaves * 4096).map(|i| (i % 251) as u8).collect();
    let mut chunks = HashMap::new();
    let file = swarm_file(&data, &mut chunks);
    let leaves: Vec<[u8; 32]> = data
        .chunks(4096)
        .map(|l| fc_swarm::chunk_address(l.len() as u64, l).unwrap())
        .collect();
    let second_leaves = &leaves[128..leaves.len().min(256)];
    let payload: Vec<u8> = second_leaves.iter().flat_map(|a| a.to_vec()).collect();
    let second = fc_swarm::chunk_address(second_leaves.len() as u64 * 4096, &payload).unwrap();
    let value = swarm_file(&mantaray(&file, &[]), &mut chunks);
    let meta = Some(r#"{"Content-Type":"application/octet-stream"}"#.to_owned());
    let root = mantaray(&[0; 32], &[(b"a".to_vec(), value, meta)]);
    let address = swarm_file(&root, &mut chunks);
    (
        hex::encode(address),
        chunks,
        data,
        format!("/chunks/{}", hex::encode(second)),
        127 * 4096,
    )
}

/// A Swarm request through main, the hashing pool and a page that reads at
/// once, against an Ant that answers `/chunks` from `chunks`, holding
/// `held`'s answer back until nothing else moves, and `/bytes` from `file`
/// in frames of at most `frame` bytes, main taking the outputs as `poll`
/// says: as `drive`.
fn swarm_stream_drive(
    v: &mut Verifier,
    chunks: &World,
    file: &[u8],
    held: &str,
    frame: usize,
    poll: Poll,
) -> (Option<u16>, usize, String) {
    struct Bytes {
        id: PieceId,
        at: usize,
        end: usize,
        sent: usize,
        credited: usize,
        cancelled: bool,
    }
    let mut jobs = VecDeque::new();
    let mut asked = VecDeque::new();
    let mut waiting = None;
    let mut stream: Option<Bytes> = None;
    let (mut head, mut body) = (None, 0);
    let mut take = true;
    loop {
        PEAK.fetch_max(v.reserved(), Ordering::Relaxed);
        assert_eq!(v.over_released(), 0, "released without a hold");
        let taken = take || poll == Poll::Each;
        take = false;
        let mut credits = 0;
        while taken && let Some(o) = v.poll() {
            match o {
                Output::Piece(r) => asked.push_back(r),
                Output::CancelPiece(id) => {
                    if let Some(s) = stream.as_mut().filter(|s| s.id == id) {
                        s.cancelled = true;
                    }
                }
                Output::Credit { piece, bytes } => {
                    credits += 1;
                    CREDITS_WAITING.fetch_max(credits, Ordering::Relaxed);
                    if let Some(s) = stream.as_mut().filter(|s| s.id == piece) {
                        s.credited += bytes;
                    }
                }
                Output::Hash(job) => jobs.push_back(job),
                Output::Head(h) => head = Some(h.status),
                Output::Body(b) => {
                    body += b.len();
                    let n = b.len();
                    drop(b);
                    credits = 0;
                    input(v, |v| v.body_credit(n)).unwrap();
                }
                Output::End => return (head, body, "end".to_owned()),
                Output::Error(e) => {
                    return (head, body, format!("error {} {}", e.status, e.message));
                }
                Output::Abort { code, message } => {
                    return (head, body, format!("abort {} {message}", code.as_str()));
                }
                Output::Cancelled => return (head, body, "cancelled".to_owned()),
                Output::Remember { .. } | Output::Floor { .. } => {}
            }
        }
        between(v);
        if let Some(job) = next_job(&mut jobs) {
            input(v, |v| v.hashed(job.run())).unwrap();
            continue;
        }
        if let Some(r) = asked.pop_front() {
            if r.stream {
                let range = r.headers.iter().find(|(n, _)| n == "range").unwrap();
                let (a, b) = range
                    .1
                    .strip_prefix("bytes=")
                    .unwrap()
                    .split_once('-')
                    .unwrap();
                let (at, end): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
                let content_range = format!("bytes {at}-{end}/{}", file.len());
                input(v, |v| {
                    v.piece_head(r.id, 206, vec![("content-range".to_owned(), content_range)])
                })
                .unwrap();
                stream = Some(Bytes {
                    id: r.id,
                    at,
                    end,
                    sent: 0,
                    credited: 0,
                    cancelled: false,
                });
            } else if r.path == held {
                waiting = Some(r);
            } else {
                input(v, |v| {
                    v.piece_whole(r.id, 200, vec![], chunks[&r.path].to_vec())
                })
                .unwrap();
            }
            continue;
        }
        if let Some(s) = stream.as_mut() {
            if s.cancelled || s.at > s.end {
                input(v, |v| v.piece_end(s.id)).unwrap();
                stream = None;
                continue;
            }
            let room = STREAM_WINDOW - (s.sent - s.credited);
            if room > 0 {
                let n = room.min(frame).min(s.end + 1 - s.at);
                input(v, |v| v.piece_data(s.id, file[s.at..s.at + n].to_vec())).unwrap();
                s.at += n;
                s.sent += n;
                continue;
            }
        }
        if taken && let Some(r) = waiting.take() {
            input(v, |v| {
                v.piece_whole(r.id, 200, vec![], chunks[&r.path].to_vec())
            })
            .unwrap();
            continue;
        }
        if !taken {
            take = true;
            continue;
        }
        return (head, body, "stalled".to_owned());
    }
}

/// A file node over raw leaves of these lengths, each its own block: its
/// root and the gateway's raw blocks.
fn raw_file(lens: &[usize]) -> (Vec<u8>, World) {
    let mut world = HashMap::new();
    let mut links = Vec::new();
    let mut data = Vec::new();
    field_varint(1, 2, &mut data);
    field_varint(3, lens.iter().sum::<usize>() as u64, &mut data);
    for (i, &len) in lens.iter().enumerate() {
        let leaf: Vec<u8> = (0..len).map(|j| ((i + j) % 251) as u8).collect();
        let cid = sha256_cid(0x55, &leaf);
        world.insert(format!("/ipfs/{}?format=raw", text(&cid)), Arc::new(leaf));
        links.push((cid, String::new(), len as u64));
        field_varint(4, len as u64, &mut data);
    }
    let block = pb_node(&links, &data);
    let root = sha256_cid(0x70, &block);
    world.insert(format!("/ipfs/{}?format=raw", text(&root)), Arc::new(block));
    (root, world)
}

/// A request's memory against its scheme's allowance: what the allocator
/// held past the reservation, between inputs and at its peak.
fn within_allowance(case: &str, m: Measured, allowance: usize) {
    let between = BETWEEN.load(Ordering::Relaxed);
    {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "{case}: allocated {} at peak, reserved {}, past it between inputs {between}, \
             within one {}, at a release {}, credits waiting at once {}",
            m.allocated,
            m.reserved,
            IN_INPUT.load(Ordering::Relaxed),
            AT_RELEASE.load(Ordering::Relaxed),
            CREDITS_WAITING.load(Ordering::Relaxed)
        );
    }
    assert!(
        between <= allowance,
        "{case}: {between} past the reservation"
    );
    let in_input = IN_INPUT.load(Ordering::Relaxed);
    assert!(
        in_input <= allowance,
        "{case}: {in_input} past the reservation within an input"
    );
    assert!(
        m.allocated <= m.reserved + allowance,
        "{case}: {m:?} past the allowance {allowance}"
    );
}

#[test]
fn allocations_stay_within_the_grant() {
    let _one = one_at_a_time();
    let raw = |budget| Options {
        budget,
        car: false,
        ..Options::default()
    };
    // Main frames a stream as it likes, and polls as seldom as it likes:
    // one byte a frame holds what 64 KiB frames do, whether main takes the
    // outputs after every input or only once nothing moves without them.
    // The CAR of 400,000 empty sections, its jobs held back, so its stream
    // waits in the stash until credit stops it.
    let (root, world) = flood();
    for poll in [Poll::Each, Poll::WhenStuck] {
        let mut at = Vec::new();
        for frame in [1, MAX_FRAME] {
            let case = format!("CAR of 400,000 empty sections, {frame}-byte frames, {poll:?}");
            let (got, m) = capped(&case, &plan(&root), REQUEST_BUDGET, |v| {
                drive_paged(v, &world, true, frame, true, poll)
            });
            assert_eq!(
                (got.0, got.1, got.2.as_str()),
                (Some(200), 200, "end"),
                "{got:?}"
            );
            within_allowance(&case, m, IPFS_ALLOWANCE);
            at.push((m, BETWEEN.load(Ordering::Relaxed)));
        }
        assert!(
            at[0].0.allocated <= at[1].0.allocated + (16 << 10),
            "{at:?}"
        );
    }
    // The Swarm walk's stream the same, its stash filling for the chunk
    // held back.
    let (root, chunks, file, held, from) = stashed_swarm_file(3 * 128);
    let mut p = swarm_plan(&root, "/a");
    p.headers = vec![("range".to_owned(), format!("bytes={from}-"))];
    for poll in [Poll::Each, Poll::WhenStuck] {
        let mut at = Vec::new();
        for frame in [1, MAX_FRAME] {
            let case = format!("Swarm stream into its stash, {frame}-byte frames, {poll:?}");
            let (got, m) = capped(&case, &p, SWARM_BUDGET, |v| {
                swarm_stream_drive(v, &chunks, &file, &held, frame, poll)
            });
            assert_eq!(
                (got.0, got.1, got.2.as_str()),
                (Some(206), file.len() - from, "end"),
                "{got:?}"
            );
            within_allowance(&case, m, SWARM_ALLOWANCE);
            at.push((m, BETWEEN.load(Ordering::Relaxed)));
        }
        assert!(
            at[0].0.allocated <= at[1].0.allocated + (16 << 10),
            "{at:?}"
        );
    }
    // A lookup whose jobs main holds back and then runs back to back
    // without polling: of the verified chunks for the cache, at most four
    // copies wait for it.
    let (root, chunks, _, _) = big_manifest();
    let p = swarm_plan(&root, "/a/q");
    let case = "manifest, nodes of 420 KB, jobs held and run unpolled";
    let (got, m) = capped(case, &p, SWARM_BUDGET, |v| {
        swarm_drive_watching(v, &chunks, Poll::WhenStuck, true, |_, _| {})
    });
    assert_eq!((got.0, got.2.as_str()), (Some(404), "end"), "{got:?}");
    within_allowance(case, m, SWARM_ALLOWANCE);
    // A stream that ends with bytes still in its stash, 80 KiB of them
    // waiting for the chunk held back: its window stays held for them.
    let (root, chunks, file, held, from) = stashed_swarm_file(148);
    let mut p = swarm_plan(&root, "/a");
    p.headers = vec![("range".to_owned(), format!("bytes={from}-"))];
    let case = "Swarm stream ended with its stash full";
    let (got, m) = capped(case, &p, SWARM_BUDGET, |v| {
        swarm_stream_drive(v, &chunks, &file, &held, MAX_FRAME, Poll::Each)
    });
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(206), file.len() - from, "end"),
        "{got:?}"
    );
    within_allowance(case, m, SWARM_ALLOWANCE);
    // Raw leaves of 1,800,000 bytes in 64 KiB frames: each buffer is made
    // once, at the leaf's length.
    let (root, world) = raw_file(&[1_800_000; 4]);
    let case = "four raw leaves of 1,800,000 bytes";
    let (got, m) = capped_with(case, &plan(&root), raw(REQUEST_BUDGET), |v| {
        drive(v, &world, false)
    });
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), 7_200_000, "end"),
        "{got:?}"
    );
    within_allowance(case, m, IPFS_ALLOWANCE);
    // A directory's block of 1.14 MB, of a length nothing gives, read raw:
    // its buffer moves to its bound once, the old one beside it held, and
    // is cut to its length at its end.
    let (root, block) = directory_block(60_000);
    assert!(block.len() > 1_114_112, "{}", block.len());
    let mut world = HashMap::new();
    world.insert(format!("/ipfs/{}?format=raw", text(&root)), Arc::new(block));
    let case = "a directory's block of 1.14 MB, read raw";
    let (got, m) = capped_with(case, &plan(&root), raw(2 * REQUEST_BUDGET), |v| {
        drive(v, &world, false)
    });
    assert_eq!((got.0, got.2.as_str()), (Some(200), "end"), "{got:?}");
    within_allowance(case, m, IPFS_ALLOWANCE);
    // The buffers alone, their blocks' bytes not copied: one byte of a
    // raw leaf of 1,800,000 bytes, in 64 KiB frames, whose buffer is made
    // once at the leaf's length; and one name in a directory's block of
    // 1.15 MB, of a length nothing gives, whose buffer moves to its bound
    // with the old one beside it held, and is cut to its length within
    // room held for the copy. The allocator's peak is within the
    // reservation's, past the machine's own structures.
    let (root, world) = raw_file(&[1_800_000]);
    let mut p = plan(&root);
    p.headers = vec![("range".to_owned(), "bytes=0-0".to_owned())];
    let case = "one byte of a raw leaf of 1,800,000 bytes";
    let (got, m) = capped_with(case, &p, raw(REQUEST_BUDGET), |v| drive(v, &world, false));
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(206), 1, "end"),
        "{got:?}"
    );
    within_allowance(case, m, MACHINE);
    let (root, block) = names_block(64_000);
    assert!(block.len() > 1_114_112, "{}", block.len());
    let mut world = HashMap::new();
    world.insert(format!("/ipfs/{}?format=raw", text(&root)), Arc::new(block));
    let mut p = plan(&root);
    p.path = "/f00001".to_owned();
    let case = "one name in a directory's block of 1.15 MB";
    let (got, m) = capped_with(case, &p, raw(REQUEST_BUDGET), |v| drive(v, &world, false));
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), 0, "end"),
        "{got:?}"
    );
    within_allowance(case, m, MACHINE);
    // A block of unknown length near its bound, whose buffer moves to the
    // bound but has no room to be cut at its end: it keeps its buffer, and
    // the buffer's room, until it goes.
    let (root, block) = names_block_padded(48_000, 22);
    assert!(block.len() > 1_900_000, "{}", block.len());
    let mut world = HashMap::new();
    world.insert(format!("/ipfs/{}?format=raw", text(&root)), Arc::new(block));
    let mut p = plan(&root);
    p.path = format!("/f00001{}", "x".repeat(22));
    let case = "one name in a directory block of 1.92 MB, no room to cut it";
    let (got, m) = capped_with(case, &p, raw(7 << 19), |v| drive(v, &world, false));
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), 0, "end"),
        "{got:?}"
    );
    within_allowance(case, m, MACHINE);
    // Slices that leave a joined tail room past its bytes, for a page that
    // doesn't read: leaves of 8,200 and 100 bytes in turn. A tail that
    // stops being one gives that room back.
    let lens: Vec<usize> = (0..128)
        .map(|i| if i % 2 == 0 { 8_200 } else { 100 })
        .collect();
    let (root, world) = raw_file(&lens);
    let case = "leaves of 8,200 and 100 bytes, a page that doesn't read";
    let (got, m) = capped_with(case, &plan(&root), raw(REQUEST_BUDGET), |v| {
        drive_paged(v, &world, false, MAX_FRAME, false, Poll::Each)
    });
    assert_eq!((got.0, got.2.as_str()), (Some(200), "stalled"), "{got:?}");
    within_allowance(case, m, IPFS_ALLOWANCE);
    // Many small slices of body: 65,536 one-byte leaves join the queue's
    // tail and main's frames.
    let (root, world) = wide_file(65_536);
    let case = "file, 65,536 one-byte leaves";
    let (got, m) = capped(case, &plan(&root), REQUEST_BUDGET, |v| {
        drive(v, &world, false)
    });
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), 65_536, "end"),
        "{got:?}"
    );
    within_allowance(case, m, IPFS_ALLOWANCE);
    // A file node of 4,000 raw leaves: their CIDs are queued at once, each
    // within the room held for them.
    let (root, world) = raw_file(&[1; 4_000]);
    let case = "a file node of 4,000 one-byte raw leaves";
    let (got, m) = capped_with(case, &plan(&root), raw(REQUEST_BUDGET), |v| {
        drive(v, &world, false)
    });
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), 4_000, "end"),
        "{got:?}"
    );
    within_allowance(case, m, IPFS_ALLOWANCE);
    // The flood's empty sections, then a section of a whole 2 MiB block,
    // whose buffer the reader makes as soon as it reads its length, in the
    // push that completes the empty ones, so the reader's room is full: the
    // vector the empty ones come in has room of its own beside it, and the
    // reader goes before its room when the CAR gives way.
    let (root, world) = flood_then(4_000, 2 << 20);
    for poll in [Poll::Each, Poll::WhenStuck] {
        let case = format!("CAR of 4,000 empty sections and one of 2 MiB, {poll:?}");
        let (got, m) = capped(&case, &plan(&root), REQUEST_BUDGET, |v| {
            drive_paged(v, &world, true, MAX_FRAME, true, poll)
        });
        assert_eq!(
            (got.0, got.1, got.2.as_str()),
            (Some(200), 200, "end"),
            "{got:?}"
        );
        within_allowance(&case, m, IPFS_ALLOWANCE);
    }
}

/// A stream's whole first window in one-byte frames, main not polling
/// until it has sent them all (each frame is within the window main was
/// given): every frame owes the stream credit, and the credit waits for
/// main as one output carrying all of it, so the request stays within its
/// scheme's grant. Before, each frame queued a credit of its own: 131,072
/// outputs, 23 MB allocated beside 2.2 MB reserved. IPFS: a raw block of
/// unknown length, read raw, at the IPFS budget. Swarm: a file's `/bytes`
/// stream, at the Swarm budget.
#[test]
fn a_window_of_one_byte_frames_unpolled_stays_within_the_grant() {
    let _one = one_at_a_time();
    let block: Vec<u8> = (0..3 * STREAM_WINDOW + 1_000)
        .map(|i| (i % 251) as u8)
        .collect();
    let root = sha256_cid(0x55, &block);
    let len = block.len();
    let mut world = HashMap::new();
    world.insert(format!("/ipfs/{}?format=raw", text(&root)), Arc::new(block));
    let options = Options {
        budget: IPFS_BUDGET,
        car: false,
        ..Options::default()
    };
    let case = "a raw block of unknown length, one-byte frames, unpolled";
    let (got, m) = capped_with(case, &plan(&root), options, |v| {
        drive_paged(v, &world, false, 1, true, Poll::WhenStuck)
    });
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), len, "end"),
        "{got:?}"
    );
    assert_eq!(CREDITS_WAITING.load(Ordering::Relaxed), 1, "{case}");
    within_allowance(case, m, IPFS_ALLOWANCE);
    assert!(m.allocated <= IPFS_GRANT, "{case}: {m:?}");

    let (root, chunks, file, _, _) = stashed_swarm_file(3 * 128);
    let p = swarm_plan(&root, "/a");
    let case = "a Swarm file's stream, one-byte frames, unpolled";
    let (got, m) = capped(case, &p, SWARM_BUDGET, |v| {
        swarm_stream_drive(v, &chunks, &file, "", 1, Poll::WhenStuck)
    });
    assert_eq!(
        (got.0, got.1, got.2.as_str()),
        (Some(200), file.len(), "end"),
        "{got:?}"
    );
    assert_eq!(CREDITS_WAITING.load(Ordering::Relaxed), 1, "{case}");
    within_allowance(case, m, SWARM_ALLOWANCE);
    assert!(m.allocated <= SWARM_GRANT, "{case}: {m:?}");
}

// ---------------------------------------------------------------------------
// The IPFS walk's values, each charged.

/// An Ed25519 IPNS name from a seed, and its signer.
fn ipns_key(seed: u8) -> (ed25519_dalek::SigningKey, String) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut name = vec![0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    name.extend_from_slice(key.verifying_key().as_bytes());
    (key, text(&name))
}

fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// A V2-only record naming `value`, valid until 2099, its signed data in
/// DAG-CBOR's canonical key order.
fn ipns_record(key: &ed25519_dalek::SigningKey, value: &str) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut data = Vec::new();
    cbor_head(5, 5, &mut data);
    let field = |k: &str, data: &mut Vec<u8>| {
        cbor_head(3, k.len() as u64, data);
        data.extend_from_slice(k.as_bytes());
    };
    field("TTL", &mut data);
    cbor_head(0, 60_000_000_000, &mut data);
    field("Value", &mut data);
    cbor_head(2, value.len() as u64, &mut data);
    data.extend_from_slice(value.as_bytes());
    field("Sequence", &mut data);
    cbor_head(0, 1, &mut data);
    field("Validity", &mut data);
    let eol = b"2099-01-01T00:00:00Z";
    cbor_head(2, eol.len() as u64, &mut data);
    data.extend_from_slice(eol);
    field("ValidityType", &mut data);
    cbor_head(0, 0, &mut data);
    let mut message = b"ipns-signature:".to_vec();
    message.extend_from_slice(&data);
    let mut out = vec![0x42, 64];
    out.extend_from_slice(&key.sign(&message).to_bytes());
    out.push(0x4a);
    varint(data.len() as u64, &mut out);
    out.extend_from_slice(&data);
    out
}

/// A name whose record names a raw leaf with `pad` bytes of path below
/// it: the record's value waits for the floor, then the path meets a file
/// (`GatewayCore`'s 502).
fn ipns_value_of(pad: usize) -> (Verify, World) {
    let leaf = b"a raw leaf".to_vec();
    let root = sha256_cid(0x55, &leaf);
    let (key, name) = ipns_key(7);
    let value = format!("/ipfs/{}/{}", text(&root), "s".repeat(pad));
    let mut world = HashMap::new();
    world.insert(format!("/ipfs/{}?format=raw", text(&root)), Arc::new(leaf));
    world.insert(
        format!("/ipns/{name}?format=ipns-record"),
        Arc::new(ipns_record(&key, &value)),
    );
    let mut p = plan(&root);
    p.root = Root::Ipns(name);
    (p, world)
}

/// A directory with one entry named `pad` bytes long: a 2,000-byte raw
/// leaf, asked for by its name, whose type is sniffed. Its tag and head
/// carry the path.
fn file_named(pad: usize) -> (Verify, World) {
    file_named_in(pad, false)
}

/// [`file_named`], the gateway answering the path's CAR too.
fn file_named_car(pad: usize) -> (Verify, World) {
    file_named_in(pad, true)
}

fn file_named_in(pad: usize, with_car: bool) -> (Verify, World) {
    let leaf: Vec<u8> = (0..2_000).map(|i| (i % 251) as u8).collect();
    let leaf_cid = sha256_cid(0x55, &leaf);
    let name = format!("f{}", "a".repeat(pad));
    let mut data = Vec::new();
    field_varint(1, 1, &mut data);
    let dir = pb_node(&[(leaf_cid.clone(), name.clone(), 2_000)], &data);
    let root = sha256_cid(0x70, &dir);
    let mut world = HashMap::new();
    world.insert(
        format!("/ipfs/{}?format=raw", text(&root)),
        Arc::new(dir.clone()),
    );
    world.insert(
        format!("/ipfs/{}?format=raw", text(&leaf_cid)),
        Arc::new(leaf.clone()),
    );
    if with_car {
        world.insert(
            format!("/ipfs/{}/{name}?format=car&dag-scope=entity", text(&root)),
            Arc::new(car(&[(root.clone(), dir), (leaf_cid, leaf)])),
        );
    }
    let mut p = plan(&root);
    p.path = format!("/{name}");
    (p, world)
}

/// A directory with one entry named `pad` bytes long, a directory of two
/// entries, listed: its title and its links' base carry the path.
fn listing_named(pad: usize) -> (Verify, World) {
    let (sub, block) = names_block(2);
    let name = format!("d{}", "a".repeat(pad));
    let mut data = Vec::new();
    field_varint(1, 1, &mut data);
    let dir = pb_node(&[(sub.clone(), name.clone(), 0)], &data);
    let root = sha256_cid(0x70, &dir);
    let mut world = HashMap::new();
    world.insert(format!("/ipfs/{}?format=raw", text(&root)), Arc::new(dir));
    world.insert(format!("/ipfs/{}?format=raw", text(&sub)), Arc::new(block));
    let mut p = plan(&root);
    p.path = format!("/{name}/");
    (p, world)
}

/// The most a request allocated past its reservation: between inputs,
/// within one, and at any release of its walk's memory.
fn past_the_reservation() -> [usize; 3] {
    [&BETWEEN, &IN_INPUT, &AT_RELEASE].map(|n| n.load(Ordering::Relaxed))
}

/// A probe for a value the IPFS walk keeps without its charge: each request
/// runs with a value of a few bytes and again with one as long as a plan's
/// path may be ([`MAX_PATH`]), and a value the walk kept uncharged would
/// show as that much more memory past the reservation, at a release of the
/// walk's memory (the record's value is live at every release while it
/// waits for the floor and is followed) or between inputs. Charged, the
/// long run passes it by no more than the short one, within 2 KiB on each
/// measure: the record's value; a file's path, tag, type and head, for a
/// HEAD the head's headers while the head waits for the input's end; the
/// path a CAR is asked for, while main hasn't taken the request; a
/// listing's path, title and base. Before the walk was charged as the
/// Swarm walk is, these were the IPFS part of the grant's allowance.
#[test]
fn an_uncharged_ipfs_value_shows_past_the_reservation() {
    let _one = one_at_a_time();
    let options = |car| Options {
        budget: IPFS_BUDGET,
        car,
        ..Options::default()
    };
    type Case = (
        &'static str,
        fn(usize) -> (Verify, World),
        u16,
        Method,
        bool,
    );
    let cases: [Case; 5] = [
        (
            "an IPNS record's value",
            ipns_value_of,
            502,
            Method::Get,
            false,
        ),
        ("a file at a long path", file_named, 200, Method::Get, false),
        (
            "a file's head at a long path",
            file_named,
            200,
            Method::Head,
            false,
        ),
        (
            "a file at a long path, by its CAR",
            file_named_car,
            200,
            Method::Get,
            true,
        ),
        (
            "a listing at a long path",
            listing_named,
            200,
            Method::Get,
            false,
        ),
    ];
    for (what, case, status, method, car) in cases {
        let ending = if method == Method::Head {
            "head"
        } else {
            "end"
        };
        let mut past = [[0; 3]; 2];
        // The longest a listing's path may be: `/d`, the name, `/`.
        for (i, pad) in [8, MAX_PATH - 3].into_iter().enumerate() {
            let label = format!("{what}, {pad} bytes");
            let (p, world) = case(pad);
            assert!(p.path.len() <= MAX_PATH, "{label}");
            let (got, m) = capped_as(&label, &p, method, options(car), |v| {
                drive(v, &world, false)
            });
            assert_eq!(
                (got.0, got.2.as_str()),
                (Some(status), ending),
                "{label}: {got:?}"
            );
            past[i] = past_the_reservation();
            within_allowance(&label, m, IPFS_ALLOWANCE);
            assert!(m.allocated <= IPFS_GRANT, "{label}: {m:?}");
        }
        for (long, short) in past[1].into_iter().zip(past[0]) {
            assert!(
                long <= short + (2 << 10),
                "{what}: past the reservation (between inputs, within one, at a \
                 release) {:?} with {} bytes more, {:?} without",
                past[1],
                MAX_PATH - 11,
                past[0]
            );
        }
    }
}

/// A plan's path (with a Swarm plan's query), and each of its headers'
/// values, are at most [`MAX_PATH`] bytes (0009, Bounds). Past it, the plan
/// is refused before anything is made of it: a 1.4 MB path below a raw
/// root allocated 8,400,476 bytes, past the 8 MiB grant, when it was
/// accepted. At it, the plan's check copies the path a few times before the
/// request's machine exists, so with nothing reserved (a budget of 0: the
/// walk ends at once, for its memory) what the request allocates is the
/// check's copies and the machine's own structures, within the allowance.
/// An IPFS plan's query, which the walk never reads, adds nothing.
#[test]
fn a_plan_past_its_path_bound_is_refused_before_it_is_copied() {
    let note = |line: &str| {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{line}");
    };
    let _one = one_at_a_time();
    let leaf = b"a raw leaf".to_vec();
    let raw_root = plan(&sha256_cid(0x55, &leaf));
    let swarm = swarm_plan(&"ab".repeat(32), "");
    // What the allocator reached making the request, and what the machine
    // reserved at its peak.
    let made = |p: &Verify| {
        Counted.reset_peak_usage();
        let base = Counted.current_usage();
        let options = Options {
            budget: 0,
            ..Options::default()
        };
        let made = Verifier::new(1, p, Method::Get, None, false, options).map(|v| v.peak());
        (made, Counted.peak_usage() - base)
    };
    let with = |p: &Verify, path: String, query: &str, headers: Vec<(String, String)>| {
        let mut p = p.clone();
        p.path = path;
        p.query = query.to_owned();
        p.headers = headers;
        p
    };
    let long = |n: usize| format!("/{}", "a".repeat(n - 1));
    let header = |name: &str, n: usize| vec![(name.to_owned(), "a".repeat(n))];
    let refused: [(&str, Verify, Refusal); 6] = [
        (
            "a 1.4 MB path below a raw root",
            with(&raw_root, format!("/{}", "a".repeat(1_400_000)), "", vec![]),
            Refusal::Path,
        ),
        (
            "an IPFS path a byte past the bound",
            with(&raw_root, long(MAX_PATH + 1), "", vec![]),
            Refusal::Path,
        ),
        (
            "a Swarm path a byte past the bound",
            with(&swarm, long(MAX_PATH + 1), "", vec![]),
            Refusal::Path,
        ),
        (
            "a Swarm path and query a byte past the bound",
            with(&swarm, long(MAX_PATH - 8), "?query=ab", vec![]),
            Refusal::Query,
        ),
        (
            "an If-None-Match a byte past the bound",
            with(
                &raw_root,
                String::new(),
                "",
                header("if-none-match", MAX_PATH + 1),
            ),
            Refusal::Header,
        ),
        (
            "a Swarm range a byte past the bound",
            with(&swarm, String::new(), "", header("range", MAX_PATH + 1)),
            Refusal::Header,
        ),
    ];
    for (what, p, refusal) in refused {
        let (got, allocated) = made(&p);
        note(&format!("{what}: {got:?}, {allocated} allocated"));
        assert_eq!(got.err(), Some(refusal), "{what}");
        assert!(allocated < 1 << 10, "{what}: {allocated} allocated");
    }
    let accepted: [(&str, Verify, usize); 5] = [
        (
            "an IPFS path at the bound",
            with(&raw_root, long(MAX_PATH), "", vec![]),
            IPFS_ALLOWANCE,
        ),
        (
            "a Swarm path at the bound",
            with(&swarm, long(MAX_PATH), "", vec![]),
            SWARM_ALLOWANCE,
        ),
        (
            "a Swarm path and query at the bound",
            with(&swarm, long(MAX_PATH - 8), "?query=a", vec![]),
            SWARM_ALLOWANCE,
        ),
        (
            "an If-None-Match and a range at the bound",
            with(
                &raw_root,
                long(MAX_PATH),
                "",
                [header("if-none-match", MAX_PATH), header("range", MAX_PATH)].concat(),
            ),
            IPFS_ALLOWANCE,
        ),
        (
            "a Swarm range at the bound",
            with(&swarm, long(MAX_PATH), "", header("range", MAX_PATH)),
            SWARM_ALLOWANCE,
        ),
    ];
    for (what, p, allowance) in accepted {
        let (got, allocated) = made(&p);
        note(&format!("{what}: {got:?}, {allocated} allocated"));
        assert_eq!(got, Ok(0), "{what}");
        assert!(allocated <= allowance, "{what}: {allocated} allocated");
    }
    // An IPFS plan's query isn't counted, and isn't copied: with a short
    // path, or one at the bound, a query to 0006's 64 KiB URL bound
    // allocates what no query does.
    for path in [long(2), long(MAX_PATH)] {
        let query = format!("?{}", "q".repeat((64 << 10) - 200 - path.len()));
        let (got, without) = made(&with(&raw_root, path.clone(), "", vec![]));
        assert_eq!(got, Ok(0));
        let (got, allocated) = made(&with(&raw_root, path.clone(), &query, vec![]));
        note(&format!(
            "an IPFS path of {} bytes with a query of {}: {got:?}, {allocated} allocated, \
             {without} without",
            path.len(),
            query.len()
        ));
        assert_eq!(got, Ok(0), "{} bytes", path.len());
        assert!(
            allocated < without + (1 << 10),
            "{} bytes: {allocated} allocated, {without} without",
            path.len()
        );
    }
}

/// A CAR's request carries the request's path: the machine counts it,
/// with its headers, from when it makes it until main takes it, by what
/// they hold.
#[test]
fn a_cars_request_is_counted_until_main_takes_it() {
    let _one = one_at_a_time();
    let (p, _) = file_named_car(MAX_PATH - 2);
    let mut v = Verifier::new(1, &p, Method::Get, None, false, Options::default()).unwrap();
    let before = v.reserved();
    let Some(Output::Piece(r)) = v.poll() else {
        panic!("no request")
    };
    assert!(
        r.path.ends_with("?format=car&dag-scope=entity"),
        "{}",
        r.path
    );
    let held = r.path.capacity()
        + r.headers.capacity() * std::mem::size_of::<(String, String)>()
        + r.headers
            .iter()
            .map(|(n, v)| n.capacity() + v.capacity())
            .sum::<usize>();
    assert!(held > MAX_PATH, "{held}");
    assert_eq!(before - v.reserved(), held);
}

/// The flood's CAR at budgets that run out while its sections pile up,
/// their jobs held back: one push into the reader completes up to 64 of
/// them, and room for one of a push's sections, with its job's structures,
/// can run out after the push's own check passed. The 64 budgets, 517
/// bytes apart, put that point at each place in a push. There the section
/// can't wait out of the reader, so the CAR gives way, and raw blocks
/// answer within the budget.
#[test]
fn a_section_without_room_gives_the_car_way() {
    let _one = one_at_a_time();
    let (root, world) = flood();
    for i in 0..64 {
        let budget = (3 << 20) + i * 517;
        let case = format!("CAR of 400,000 empty sections at {budget}");
        let (got, m) = capped(&case, &plan(&root), budget, |v| {
            drive_paged(v, &world, true, MAX_FRAME, true, Poll::Each)
        });
        assert_eq!(
            (got.0, got.1, got.2.as_str()),
            (Some(200), 200, "end"),
            "{case}: {got:?}"
        );
        assert!(m.reserved <= budget, "{case}: {m:?}");
    }
}
