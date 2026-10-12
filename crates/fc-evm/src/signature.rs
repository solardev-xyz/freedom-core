use k256::ecdsa::SigningKey;

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
