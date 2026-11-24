//! Feed writes (design 0015, "Feeds, SOCs and SW-1"), as bee-js 13.2.0's
//! feed writer builds them (`feed/index.js`, `feed/identifier.js`):
//!
//! - **the topic** of a name: `keccak256(utf8(name))` (`Topic.fromString`);
//! - **the identifier** at an index: `keccak256(topic ‖ index)`, the index
//!   as 8 bytes big-endian (`FeedIndex.fromBigInt`);
//! - **the update**, the chunk the update's single-owner chunk wraps, in
//!   the forms bee-js writes:
//!   - a reference: `timestamp ‖ reference`, the timestamp as 8 bytes
//!     big-endian (`updateFeedWithReference`);
//!   - a payload of 1 to 4,096 bytes: the payload itself, its span its
//!     length (`updateFeedWithPayload`);
//!   - a larger payload: the root chunk of its tree, its span the payload's
//!     length. bee-js wraps the root the node sends back from `GET /chunks`;
//!     the core wraps its own ([`crate::chunker`]), whose span is what it
//!     hashed (deviation `feed-wrap-root`).
//!
//! A one-chunk entry read back is held to its wrapped span
//! ([`inline_entry`]), as freedom-browser#1057 holds it.

use fc_evm::keccak256;

use crate::chunker::{Root, root_refs};
use crate::{CHUNK_SIZE, Error, PreparedChunk, prepare_soc};

pub use crate::verify::{feed_update_address as update_address, feed_update_id as identifier};

/// A reference update's payload: 8 bytes of time and a 32-byte reference.
pub const REFERENCE_PAYLOAD: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// An update carries 1 to 4,096 bytes; bee-js refuses an empty payload
    /// as it builds the chunk.
    #[error("payload size {0} outside 1..=4096")]
    PayloadSize(usize),
    /// A wrapped root is for more than one chunk of data, with the
    /// references a tree of its span has.
    #[error("a root of {payload_len} bytes doesn't wrap a {span}-byte tree")]
    Wrap { span: u64, payload_len: usize },
    /// An entry read back whose span is past what its chunk holds.
    #[error("a {span}-byte entry in a chunk of {payload_len} bytes")]
    Inline { span: u64, payload_len: usize },
}

/// A feed name's topic: `keccak256(utf8(name))`.
pub fn topic(name: &str) -> [u8; 32] {
    keccak256(name.as_bytes())
}

/// `timestamp (8 bytes, big-endian) ‖ reference`: bee-js writes
/// `Math.floor(at)`, `at` in seconds.
pub fn reference_payload(timestamp: u64, reference: &[u8; 32]) -> [u8; REFERENCE_PAYLOAD] {
    let mut out = [0u8; REFERENCE_PAYLOAD];
    out[..8].copy_from_slice(&timestamp.to_be_bytes());
    out[8..].copy_from_slice(reference);
    out
}

/// The chunk a feed update's single-owner chunk wraps: its span and
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    span: u64,
    payload: Vec<u8>,
}

impl Update {
    /// An update naming `reference`.
    pub fn reference(timestamp: u64, reference: &[u8; 32]) -> Self {
        Self {
            span: REFERENCE_PAYLOAD as u64,
            payload: reference_payload(timestamp, reference).to_vec(),
        }
    }

    /// An update carrying `data` itself: 1 to 4,096 bytes.
    pub fn inline(data: &[u8]) -> Result<Self, FeedError> {
        if data.is_empty() || data.len() > CHUNK_SIZE {
            return Err(FeedError::PayloadSize(data.len()));
        }
        Ok(Self {
            span: data.len() as u64,
            payload: data.to_vec(),
        })
    }

    /// An update wrapping the root of a payload over one chunk, as the
    /// chunker computed it from the bytes it streamed to `/bytes`. The
    /// wrap is bound to its span: more than 4,096 bytes, and exactly the
    /// references a tree of that span has at its root.
    pub fn wrap(root: &Root) -> Result<Self, FeedError> {
        let (span, payload) = (root.span(), root.payload());
        let refs = root_refs(span);
        if refs == 0 || payload.len() != refs * 32 {
            return Err(FeedError::Wrap {
                span,
                payload_len: payload.len(),
            });
        }
        Ok(Self {
            span,
            payload: payload.to_vec(),
        })
    }

    pub fn span(&self) -> u64 {
        self.span
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The update's single-owner chunk at `identifier`, ready to sign.
    pub fn prepare(&self, identifier: &[u8; 32]) -> Result<PreparedChunk, Error> {
        prepare_soc(identifier, Some(self.span), &self.payload)
    }
}

/// A one-chunk entry read back (a wrapped span of at most 4,096 bytes):
/// the chunk's payload held to that span. Bytes past the span aren't the
/// entry, and a span past the payload is an entry the chunk doesn't hold.
/// A larger span is read through `/bytes`, so it has no inline entry.
pub fn inline_entry(span: u64, payload: &[u8]) -> Result<&[u8], FeedError> {
    match usize::try_from(span) {
        Ok(len) if len <= CHUNK_SIZE && len <= payload.len() => Ok(&payload[..len]),
        _ => Err(FeedError::Inline {
            span,
            payload_len: payload.len(),
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::chunker::root_of;

    #[test]
    fn updates_hold_their_bounds() {
        assert_eq!(Update::inline(&[]), Err(FeedError::PayloadSize(0)));
        assert_eq!(
            Update::inline(&[0; 4097]),
            Err(FeedError::PayloadSize(4097))
        );
        assert_eq!(Update::inline(&[7; 4096]).unwrap().span(), 4096);
        // A root of one chunk is no wrap: its data is inline.
        let small = root_of(&[1; 4096]).unwrap();
        assert_eq!(
            Update::wrap(&small),
            Err(FeedError::Wrap {
                span: 4096,
                payload_len: 4096
            })
        );
        let large = root_of(&[1; 4097]).unwrap();
        let update = Update::wrap(&large).unwrap();
        assert_eq!((update.span(), update.payload().len()), (4097, 64));
    }

    #[test]
    fn an_inline_entry_is_held_to_its_span() {
        assert_eq!(inline_entry(2, b"abc").unwrap(), b"ab");
        assert_eq!(
            inline_entry(4, b"abc"),
            Err(FeedError::Inline {
                span: 4,
                payload_len: 3
            })
        );
        assert!(inline_entry(4097, &[0; 4096]).is_err());
        assert!(inline_entry(u64::MAX, &[0; 4096]).is_err());
    }
}
