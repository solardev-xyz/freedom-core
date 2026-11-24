//! Single-owner chunk bodies (design 0015, "Feeds, SOCs and SW-1"), as
//! core-sdk 0.2.2's `makeSingleOwnerChunk` and bee-js 13.2.0's
//! `uploadSingleOwnerChunk` lay them out:
//!
//! - **the chunk:** `identifier ‖ signature ‖ span ‖ payload`, the span 8
//!   bytes little-endian, what `/chunks` serves at the SOC's address;
//! - **the upload:** `POST /soc/<owner>/<identifier>?sig=<signature>` with
//!   the body `span ‖ payload`;
//! - **the address:** `keccak256(identifier ‖ owner)`.
//!
//! The signature comes from [`crate::sign_soc`] or
//! [`crate::PreparedChunk::finish`]. Each body is built only for the
//! payload the signature covers.

use crate::verify::SPAN_SIZE;
use crate::{Error, SignedChunk, chunk_address};

pub use crate::verify::soc_address as address;

/// The identifier and the signature before a SOC's wrapped chunk.
pub const HEADER: usize = 32 + 65;

/// Whether `payload` is the chunk `signed` signs, at `identifier`.
fn check(identifier: &[u8; 32], signed: &SignedChunk, payload: &[u8]) -> Result<(), Error> {
    if chunk_address(signed.span, payload)? != signed.chunk_address
        || address(identifier, &signed.owner) != signed.soc_address
    {
        return Err(Error::Mismatch);
    }
    Ok(())
}

/// The single-owner chunk: `identifier ‖ signature ‖ span ‖ payload`.
pub fn body(identifier: &[u8; 32], signed: &SignedChunk, payload: &[u8]) -> Result<Vec<u8>, Error> {
    check(identifier, signed, payload)?;
    let mut out = Vec::with_capacity(HEADER + SPAN_SIZE + payload.len());
    out.extend_from_slice(identifier);
    out.extend_from_slice(&signed.signature);
    out.extend_from_slice(&signed.span.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// The body of `POST /soc/<owner>/<identifier>`: `span ‖ payload`.
pub fn upload_body(
    identifier: &[u8; 32],
    signed: &SignedChunk,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    check(identifier, signed, payload)?;
    let mut out = Vec::with_capacity(SPAN_SIZE + payload.len());
    out.extend_from_slice(&signed.span.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use k256::ecdsa::SigningKey;

    use super::*;
    use crate::sign_soc;
    use crate::verify::single_owner;

    #[test]
    fn a_body_reads_back_as_its_soc() {
        let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let id = [3u8; 32];
        let signed = sign_soc(&key, &id, None, b"payload").unwrap();
        let wire = body(&id, &signed, b"payload").unwrap();
        let soc = single_owner(&signed.soc_address, &wire).unwrap();
        assert_eq!((soc.id, soc.owner), (id, signed.owner));
        assert_eq!(soc.chunk.payload, b"payload");
        assert_eq!(
            upload_body(&id, &signed, b"payload").unwrap(),
            wire[HEADER..].to_vec()
        );
    }

    #[test]
    fn a_body_is_only_for_the_signed_payload() {
        let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let id = [3u8; 32];
        let signed = sign_soc(&key, &id, None, b"payload").unwrap();
        assert_eq!(body(&id, &signed, b"other"), Err(Error::Mismatch));
        assert_eq!(
            upload_body(&[4u8; 32], &signed, b"payload"),
            Err(Error::Mismatch)
        );
    }
}
