//! A block against its CID: freedom-ipfs's `verify_block` (sha2-256 and
//! identity, at most 2 MiB), and the codecs the walk reads (dag-pb, raw).

use sha2::{Digest, Sha256};

use crate::Refusal;
use crate::cid::{Cid, DAG_PB, IDENTITY, RAW, SHA2_256};

/// The native node's block limit.
pub const MAX_BLOCK: usize = 2 * 1024 * 1024;

/// Checks `block` against `cid`, as the native node does, then the codec.
/// A hash function the native node doesn't verify, or a codec the walk
/// doesn't read, is unverifiable; anything else that fails is a
/// verification failure.
pub fn check(cid: &Cid<'_>, block: &[u8]) -> Result<(), Refusal> {
    if block.len() > MAX_BLOCK {
        return Err(Refusal::VerificationFailed);
    }
    match cid.hash {
        SHA2_256 => {
            if Sha256::digest(block).as_slice() != cid.digest {
                return Err(Refusal::VerificationFailed);
            }
        }
        IDENTITY => {
            if block != cid.digest {
                return Err(Refusal::VerificationFailed);
            }
        }
        _ => return Err(Refusal::Unverifiable),
    }
    if cid.codec != DAG_PB && cid.codec != RAW {
        return Err(Refusal::Unverifiable);
    }
    Ok(())
}
