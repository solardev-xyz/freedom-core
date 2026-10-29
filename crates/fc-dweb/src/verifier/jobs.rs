//! Hash jobs (design 0009, `dweb.verify`'s Thread): the hashing a walk
//! needs leaves the machine as a [`Job`], so the dweb thread can run it on
//! its pool of two hashing threads, and comes back as [`Hashed`]. A job
//! owns the bytes it checks, and its result hands them back, so nothing is
//! copied and the request's memory still counts them while they are out.
//!
//! [`Job::run`] is the only way to make a [`Hashed`]: the machine trusts a
//! result's verdict because the job's own code produced it, and it refuses
//! one it didn't ask for or got already ([`super::Misuse`]).

use fc_ipfs::Refusal as BlockRefusal;
use fc_ipfs::ipns::Record;
use fc_swarm::verify::{self, FeedUpdate, Refusal};

/// A job's identity: the `dweb.verify` request it belongs to and its number
/// within that request, so another request's result is refused too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId {
    pub request: u64,
    pub seq: u64,
}

/// What a job checks.
#[derive(Debug, Clone)]
pub(crate) enum Work {
    /// A piece the walk needs as a content-addressed chunk.
    Chunk { address: [u8; 32], wire: Vec<u8> },
    /// A feed update at the address the walk computed.
    FeedUpdate {
        owner: [u8; 20],
        topic: [u8; 32],
        index: u64,
        wire: Vec<u8>,
    },
    /// A leaf's streamed bytes against the address its parent names.
    Leaf {
        address: [u8; 32],
        len: usize,
        bytes: Vec<u8>,
    },
    /// A leaf whose streamed bytes didn't match, against `/chunks`'s answer.
    LeafChunk {
        address: [u8; 32],
        len: usize,
        bytes: Vec<u8>,
        wire: Vec<u8>,
    },
    /// An IPFS block against its CID (`fc_ipfs::block::check`).
    Block { cid: Vec<u8>, block: Vec<u8> },
    /// An IPNS record for the name whose CID is `name`, at `now`.
    Record {
        name: Vec<u8>,
        record: Vec<u8>,
        now: i64,
    },
}

impl Work {
    /// The bytes it holds, which the request's memory counts.
    pub(crate) fn size(&self) -> usize {
        match self {
            Self::Chunk { wire, .. } | Self::FeedUpdate { wire, .. } => wire.len(),
            Self::Leaf { bytes, .. } => bytes.len(),
            Self::LeafChunk { bytes, wire, .. } => bytes.len() + wire.len(),
            Self::Block { cid, block } => cid.len() + block.len(),
            Self::Record { name, record, .. } => name.len() + record.len(),
        }
    }
}

/// A job's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Chunk(Result<(), Refusal>),
    FeedUpdate(Result<FeedUpdate, Refusal>),
    /// Whether the streamed bytes hash to the address.
    Leaf(bool),
    LeafChunk(Result<(), Refusal>),
    Block(Result<(), BlockRefusal>),
    Record(Result<Record, BlockRefusal>),
}

/// Work for the hashing pool. Run it with [`Job::run`] and hand the result
/// to [`super::Verifier::hashed`].
#[derive(Debug, Clone)]
pub struct Job {
    pub(crate) id: JobId,
    pub(crate) work: Work,
}

impl Job {
    pub fn id(&self) -> JobId {
        self.id
    }

    /// The bytes it carries: what the pool's queue holds for it.
    pub fn size(&self) -> usize {
        self.work.size()
    }

    /// Does the hashing: BMT roots and keccak, a feed update's signature
    /// recovery, an IPFS block's digest, an IPNS record's signature.
    pub fn run(self) -> Hashed {
        let verdict = match &self.work {
            Work::Chunk { address, wire } => {
                Verdict::Chunk(verify::check_chunk(address, wire).map(|_| ()))
            }
            Work::FeedUpdate {
                owner,
                topic,
                index,
                wire,
            } => Verdict::FeedUpdate(verify::check_feed_update(owner, topic, *index, wire)),
            Work::Leaf {
                address,
                len,
                bytes,
            } => Verdict::Leaf(verify::leaf_matches(address, *len, bytes)),
            Work::LeafChunk {
                address,
                len,
                bytes,
                wire,
            } => Verdict::LeafChunk(verify::check_leaf_chunk(address, *len, bytes, wire)),
            Work::Block { cid, block } => Verdict::Block(match fc_ipfs::cid::parse(cid) {
                Some(cid) => fc_ipfs::block::check(&cid, block),
                None => Err(BlockRefusal::VerificationFailed),
            }),
            Work::Record { name, record, now } => Verdict::Record(match fc_ipfs::cid::parse(name) {
                Some(name) => fc_ipfs::ipns::check(&name, record, *now),
                None => Err(BlockRefusal::Unverifiable),
            }),
        };
        Hashed {
            id: self.id,
            work: self.work,
            verdict,
        }
    }
}

/// A job's result: its id, its verdict and the bytes it held.
#[derive(Debug, Clone)]
pub struct Hashed {
    pub(crate) id: JobId,
    pub(crate) work: Work,
    pub(crate) verdict: Verdict,
}

impl Hashed {
    pub fn id(&self) -> JobId {
        self.id
    }
}
