//! IPFS content as verified mode reads it from an external gateway (design
//! 0009, IPFS): CIDs and the native node's block check, the bounded
//! protobuf and DAG-CBOR readers, dag-pb and UnixFS with the stricter size
//! rules, HAMT lookup by hash, and a streaming CAR reader.
//!
//! A logic crate: no I/O, and no decoder allocates from a count it hasn't
//! checked (AGENTS.md rule 2; 0009, Bounded decoding). It owns its CID and
//! block-check code, held to freedom-ipfs's by vectors, so the core doesn't
//! depend on freedom-ipfs at run time (decided: one pin).
//! `vectors/dweb-verify-cases.json` (ipfs) and `vectors/dweb-verify.json`
//! are the contract.

pub mod block;
pub mod car;
pub mod cbor;
pub mod cid;
pub mod dagpb;
pub mod hamt;
mod murmur3;
pub mod path;
pub mod pb;
pub mod unixfs;
pub mod varint;

/// Why content is refused (0009, Failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The bytes aren't what their CID commits to, or the framing around
    /// them is broken.
    VerificationFailed,
    /// Possibly authentic, but outside what the core checks: an unsupported
    /// hash or codec, structure past the decoders' caps.
    Unverifiable,
    /// Authentic content that can't be decoded or is inconsistent.
    Malformed,
}
