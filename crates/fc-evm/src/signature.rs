use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

use crate::{Error, keccak256};

/// Signs a 32-byte digest: RFC 6979 nonce, low-s, `r ‖ s ‖ v` with
/// `v ∈ {27, 28}` (ethers' `Signature.serialized`). Also returns the y parity.
pub(crate) fn sign_prehash(key: &SigningKey, digest: &[u8; 32]) -> Result<([u8; 65], u8), Error> {
    let (signature, recovery) = key.sign_prehash_recoverable(digest);
    // An x-coordinate reduced mod n can't be expressed in an Ethereum `v`;
    // its probability is about 2^-128.
    if recovery.is_x_reduced() {
        return Err(Error::Signing);
    }
    let parity = u8::from(recovery.is_y_odd());
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = 27 + parity;
    Ok((out, parity))
}

/// Signs a 32-byte digest as is.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Result<[u8; 65], Error> {
    sign_prehash(key, digest).map(|(signature, _)| signature)
}

/// `keccak256("\x19Ethereum Signed Message:\n" ‖ len ‖ message)` (EIP-191).
pub fn eip191_digest(message: &[u8]) -> [u8; 32] {
    let mut data = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    data.extend_from_slice(message);
    keccak256(&data)
}

/// `Wallet.signMessage(bytes)`.
pub fn sign_message(key: &SigningKey, message: &[u8]) -> Result<[u8; 65], Error> {
    sign_digest(key, &eip191_digest(message))
}

/// `Wallet.signTypedData(domain, types, message)`.
pub fn sign_typed_data(
    key: &SigningKey,
    domain: &serde_json::Value,
    types: &serde_json::Value,
    message: &serde_json::Value,
) -> Result<[u8; 65], Error> {
    sign_digest(key, &crate::typed_data_hash(domain, types, message)?)
}

/// The address whose key made `signature`, `r ‖ s ‖ v`, over a 32-byte
/// digest, read as Ant v0.5.71 and Bee read a single-owner chunk's
/// signature (design 0009, Chunks):
///
/// - `v` is 27 to 30, and its recovery id is `v − 27`: 29 and 30 name an
///   `r` reduced mod the curve order, any other `v` is refused;
/// - `s` must be low (at most half the curve order). k256 0.13, which Ant
///   uses, refuses a high `s` when it checks the recovered key; k256 0.14's
///   recovery doesn't check, so the core refuses it here;
/// - a signature whose `r` or `s` is zero or past the order, or whose point
///   doesn't exist, is refused.
///
/// No key is involved; the digest is whatever the caller hashed (for a
/// single-owner chunk, the EIP-191 digest of `keccak256(id ‖ address)`).
pub fn recover_address(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20], Error> {
    let recovery = signature[64]
        .checked_sub(27)
        .and_then(RecoveryId::from_byte)
        .ok_or(Error::Recovery)?;
    let parsed = Signature::from_slice(&signature[..64]).map_err(|_| Error::Recovery)?;
    if parsed.normalize_s() != parsed {
        return Err(Error::Recovery);
    }
    let key = VerifyingKey::recover_from_prehash(digest, &parsed, recovery)
        .map_err(|_| Error::Recovery)?;
    Ok(crate::address::address_of_public(&key))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use k256::elliptic_curve::PrimeField;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&keccak256(b"recover-address").into()).unwrap()
    }

    fn signed(digest: &[u8; 32]) -> [u8; 65] {
        sign_digest(&key(), digest).unwrap()
    }

    #[test]
    fn recovers_the_signer() {
        let digest = keccak256(b"a digest");
        let address = crate::address_of(&key());
        assert_eq!(recover_address(&digest, &signed(&digest)), Ok(address));
    }

    #[test]
    fn another_digest_recovers_another_address() {
        let digest = keccak256(b"a digest");
        let other = keccak256(b"another digest");
        let address = crate::address_of(&key());
        assert_ne!(recover_address(&other, &signed(&digest)), Ok(address));
    }

    #[test]
    fn the_other_parity_recovers_another_address() {
        let digest = keccak256(b"a digest");
        let mut sig = signed(&digest);
        sig[64] = if sig[64] == 27 { 28 } else { 27 };
        assert_ne!(
            recover_address(&digest, &sig),
            Ok(crate::address_of(&key()))
        );
    }

    #[test]
    fn high_s_is_refused() {
        let digest = keccak256(b"a digest");
        let mut sig = signed(&digest);
        let s_bytes: [u8; 32] = sig[32..64].try_into().unwrap();
        let s = k256::Scalar::from_repr(s_bytes.into()).unwrap();
        sig[32..64].copy_from_slice(&(-s).to_repr());
        sig[64] = if sig[64] == 27 { 28 } else { 27 };
        // The same signature, mathematically, in its high-s form.
        assert_eq!(recover_address(&digest, &sig), Err(Error::Recovery));
    }

    #[test]
    fn only_v_27_to_30_is_read() {
        let digest = keccak256(b"a digest");
        for v in [0u8, 1, 26, 31, 255] {
            let mut sig = signed(&digest);
            sig[64] = v;
            assert_eq!(
                recover_address(&digest, &sig),
                Err(Error::Recovery),
                "v = {v}"
            );
        }
        // 29 and 30 name an r past the order, which this r isn't.
        for v in [29u8, 30] {
            let mut sig = signed(&digest);
            sig[64] = v;
            assert_ne!(
                recover_address(&digest, &sig),
                Ok(crate::address_of(&key())),
                "v = {v}"
            );
        }
    }

    #[test]
    fn zero_or_overflowing_scalars_are_refused() {
        let digest = keccak256(b"a digest");
        let mut zero_r = signed(&digest);
        zero_r[..32].fill(0);
        assert_eq!(recover_address(&digest, &zero_r), Err(Error::Recovery));
        let mut max_s = signed(&digest);
        max_s[32..64].fill(0xff);
        assert_eq!(recover_address(&digest, &max_s), Err(Error::Recovery));
    }
}
